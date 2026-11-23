"""The Homebrew findings of `doctor`, and what `doctor --fix` needs to know about their remedies

The detectors read the scan, adding only one `brew doctor` per drivable instance and a lock-free `git status`
of each repository.
"""

from __future__ import annotations

import glob
import os
import shlex
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .. import env, model, system
from ..env import linkage as env_linkage, services as env_services, shell as env_shell
from ..model import Action, Blocks, Issue, OnFailure, Package, Severity
from ..report import (MOVE_OUT, NAMES_SHOWN, NOT_CHECKED, at, by_kind, counted, limited, offered, series, some,
                      tilde)
from ..runner import BREW_DENY, BREW_DENY_PREFIXES, BREW_SET, RM
from ..state import slug
from . import actions, inventory, locate
from .catalogue import (Artifact, Catalogue, artifact_targets, cask_dirs, dirs_from_config, normalise_artifacts,
                        plain_keys, plain_symbol, version_key)

if TYPE_CHECKING:
    from ..scan import ScanBundle

GIT = inventory.GIT
LAUNCHCTL = system.LAUNCHCTL
TAR = system.TAR
CORE_TAP = "homebrew/core"
STALE_S = 7 * 86400                     # an older API file makes the catalogue stale
FALSY = frozenset(("false", "no", "off", "nil", "0"))     # Homebrew's EnvConfig::FALSY_VALUES
WRITABLE_DIRS = ("bin", "lib", "share", "opt", "Cellar", os.path.join("var", "homebrew"))
LINK_DIRS = ("bin", "sbin", "lib", "include", "share", "etc", "opt", os.path.join("var", "homebrew", "linked"))
STASH_IDENTITY = ("author.name=brew-ports", "author.email=brew-ports@localhost",
                  "committer.name=brew-ports", "committer.email=brew-ports@localhost")
CASKFILE_EXTENSIONS = ("json", "internal.json", "rb")   # Homebrew's Caskroom::CASKFILE_EXTENSIONS

SEVERITY = {
    "brew-several-prefixes": Severity.INFO,
    "brew-unusable-or-dirty": Severity.HIGH,
    "brew-stale-catalogue": Severity.LOW,
    "brew-keg-without-receipt": Severity.HIGH,
    "brew-deleted-formula": Severity.MEDIUM,
    "brew-deprecated-formula": Severity.INFO,
    "brew-unlinked-keg": Severity.MEDIUM,
    "brew-broken-symlink": Severity.LOW,
    "brew-several-versions": Severity.LOW,
    "brew-missing-dependency": Severity.HIGH,
    "brew-broken-linkage": Severity.HIGH,
    "brew-outdated-keg": Severity.INFO,
    "brew-pinned-formula": Severity.INFO,
    "brew-dirty-tap": Severity.MEDIUM,
    "brew-unwritable-prefix": Severity.HIGH,
    "brew-orphan-service": Severity.LOW,
    "brew-missing-app": Severity.MEDIUM,
    "brew-orphan-caskroom": Severity.LOW,
    "brew-strays-in-usr-local": Severity.MEDIUM,
    "brew-path-order": Severity.LOW,
    "brew-renamed-keg": Severity.LOW,
    "brew-degraded-inventory": Severity.HIGH,
    "brew-failed-probe": Severity.INFO,
    "brew-root-owned-keg": Severity.HIGH,
    "brew-env-override": Severity.HIGH,
}
BLOCKS = {
    "brew-unusable-or-dirty": (Blocks.TARGET,),
    "brew-unwritable-prefix": (Blocks.TARGET, Blocks.UNINSTALL),
    "brew-degraded-inventory": (Blocks.TARGET, Blocks.CASKS, Blocks.REMOVE),
    "brew-root-owned-keg": (Blocks.TARGET,),
    "brew-env-override": (Blocks.ANY,),
}

# The first line of each check's finding in Homebrew 7.0.11 (diagnostic.rb).
DOCTOR_HEADLINES = {
    "check_deleted_formula": "Some installed kegs have no formulae!",
    "check_deprecated_disabled": "Some installed formulae are deprecated or disabled.",
    "check_for_unlinked_but_not_keg_only": "You have unlinked kegs in your Cellar.",
    "check_for_broken_symlinks": "Broken symlinks were found:",
    "check_for_stray_dylibs": "Unbrewed dylibs were found in /usr/local/lib.",
    "check_for_stray_static_libs": "Unbrewed static libraries were found in /usr/local/lib.",
    "check_for_stray_pcs": "Unbrewed '.pc' files were found in /usr/local/lib/pkgconfig.",
    "check_for_stray_las": "Unbrewed '.la' files were found in /usr/local/lib.",
    "check_for_stray_headers": "Unbrewed header files were found in /usr/local/include.",
}
STRAY = {   # stray-file check -> (directory, what the files are)
    "check_for_stray_dylibs": ("/usr/local/lib", "libraries"),
    "check_for_stray_static_libs": ("/usr/local/lib", "static libraries"),
    "check_for_stray_pcs": ("/usr/local/lib/pkgconfig", ".pc files"),
    "check_for_stray_las": ("/usr/local/lib", ".la files"),
    "check_for_stray_headers": ("/usr/local/include", "header files"),
}
MOVE_FINDS_IT = "A move out of this Homebrew looks up the replacement itself."
LOADS = {   # the class of a library reference that the linkage scan calls broken -> what the binary does with it
    "missing": "needs %s, which is missing",
    "other": "loads %s from another installation",
    "usrlocal": "loads %s from /usr/local",
}

_now: Callable[[], float] = time.time


# brew doctor -------------------------------------------------------------------------

@dataclass
class DoctorReport:
    """What one `brew doctor <checks...>` printed"""

    warnings: dict[str, list[str]] = field(default_factory=dict)   # check -> its finding's lines
    errors: list[str] = field(default_factory=list)                # `Error:` lines (an unknown check name)
    failure: str | None = None                                  # set when the output cannot be trusted

    def lists(self, check: str, item: str) -> bool:
        """Return whether a check's finding names `item` on one of its indented lines

        @param check  the `brew doctor` check, such as `check_for_broken_symlinks`
        @param item   a path or name; a line whose last path component it is matches too
        @returns      True when the finding lists it
        """
        for line in self.warnings.get(check, [])[1:]:
            text = line.strip()
            if line.startswith("  ") and text and item in (text, text.rsplit("/", 1)[-1]):
                return True
        return False


def parse_doctor(text: str) -> DoctorReport:
    """Parse `brew doctor`'s stderr, matching each finding to its check by Homebrew's headline

    A finding runs from `Warning: <text>` over the following lines; the preamble and unmatched findings are
    dropped.

    @param text  the stderr of `brew doctor`
    @returns     the findings by check, and the `Error:` lines
    """
    report = DoctorReport()
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("Warning: "):
            current = [line[len("Warning: "):]]
            blocks.append(current)
        elif line.startswith("Error: "):
            report.errors.append(line[len("Error: "):])
            current = None
        elif current is not None:
            current.append(line)
    checks = {headline: check for check, headline in DOCTOR_HEADLINES.items()}
    for block in blocks:
        while block and not block[-1].strip():
            block.pop()
        check = checks.get(block[0].strip()) if block else None
        if check and check not in report.warnings:
            report.warnings[check] = block
    return report


def run_doctor(runner, instance: model.Instance) -> DoctorReport:
    """Run one `brew doctor` with every needed check named on a drivable instance

    It exits 1 when a check fires; an exit 1 without a readable finding, any other exit or a timeout makes the
    report a failure.

    @param runner    the runner the probe goes through
    @param instance  the drivable Homebrew instance
    @returns         the report, its `failure` set when the output cannot be trusted
    """
    res = runner.run(actions.doctor(instance, runner.host_arch, f"0.brew.{slug(instance.prefix)}.doctor"))
    report = parse_doctor(res.stderr())
    if res.timed_out or res.exit not in (0, 1) or (res.exit == 1 and not report.warnings):
        report.failure = locate.failure_text(res, "brew doctor")
    return report


# Context -----------------------------------------------------------------------------

@dataclass
class _Brew:
    """One Homebrew instance with its catalogue, inventory and `brew doctor` report"""

    inst: model.Instance
    cat: Catalogue | None
    inv: inventory.HomebrewInventory
    doctor: DoctorReport | None = None

    @property
    def prefix(self) -> str:
        """Return the instance's prefix

        @returns  the prefix, as the instance spells it
        """
        return self.inst.prefix

    @property
    def at(self) -> str:
        """Return the installation as the report names it

        @returns  such as `Homebrew at /opt/homebrew`
        """
        return at(self.inst)

    def packages(self, kind: str) -> list[Package]:
        """Return the instance's packages of one kind, sorted by name

        @param kind  `formula` or `cask`
        @returns     the packages
        """
        return sorted((p for p in self.inv.packages if p.kind == kind), key=lambda p: p.name)

    def racks(self, pkg: Package) -> list[str]:
        """Return the Cellar racks of a formula's kegs; an unmigrated rename keeps them under the old name

        @param pkg  an installed formula
        @returns    the rack directories; `<prefix>/Cellar/<name>` when the inventory lists no keg
        """
        out: list[str] = []
        for keg in self.inv.kegs.get(pkg.name) or []:
            rack = os.path.dirname(keg)
            if rack not in out:
                out.append(rack)
        return out or [os.path.join(self.prefix, "Cellar", pkg.name)]

    def names(self, pkg: Package) -> list[str]:
        """Return the formula's name and the names of its racks

        @param pkg  an installed formula
        @returns    the names, the formula's own first
        """
        out = [pkg.name]
        out.extend(n for n in (os.path.basename(r) for r in self.racks(pkg)) if n not in out)
        return out

    def quote(self, check: str, items: Sequence[str]) -> list[str]:
        """Say that Homebrew's own check lists one of `items`

        @param check  the `brew doctor` check
        @param items  the paths or names the finding is about
        @returns      the sentence as a one-item list, or an empty list
        """
        if self.doctor is not None and any(self.doctor.lists(check, item) for item in items):
            return ["`brew doctor` reports it too"]
        return []

    def cannot_run(self) -> str:
        """Return why nothing can be asked of the installation's `brew`

        @returns  `its `brew` command cannot run`, with the first line of what the probes found
        """
        detail = (self.inst.usability_detail or "").strip().splitlines()
        return "its `brew` command cannot run" + (f": {detail[0]}" if detail else "")

    def no_fix(self, code: str, item: str) -> Action:
        """Return the note of a finding whose fix is a `brew` command, on an installation whose `brew` cannot run

        @param code  the finding's code
        @param item  the path the fix would act on, for the action id
        @returns     the note
        """
        return _note(code, item, f"No fix until the `brew` command of {self.at} runs.", "no-brew")


@dataclass
class _Scan:
    """What every detector reads: the scan bundle, the runner, the Homebrew instances and the environment"""
    bundle: Any
    runner: Any
    brews: list[_Brew]
    environ: dict[str, str]
    home: str
    now: float

    @property
    def host_arch(self) -> str:
        """Return the host's architecture

        @returns  `arm64` or `x86_64`, as the runner records it
        """
        return self.runner.host_arch

    @property
    def services(self) -> list[model.Service]:
        """Return the launchd services the scan found

        @returns  a copy of the bundle's list
        """
        return list(self.bundle.result.services)


def _context(bundle: "ScanBundle", runner) -> _Scan:
    """Build the detectors' context, running `brew doctor` once on each drivable instance

    @param bundle  the scan bundle
    @param runner  the runner the probes go through
    @returns       the context
    """
    environ = dict(runner.environ)
    brews = []
    for inst, cat, inv in bundle.brew:
        if inst.manager is not model.Manager.BREW:
            continue
        brew = _Brew(inst, cat, inv)
        if inst.drivable:
            brew.doctor = run_doctor(runner, inst)
        brews.append(brew)
    return _Scan(bundle=bundle, runner=runner, brews=brews, environ=environ,
                 home=environ.get("HOME") or os.path.expanduser("~"), now=_now())


# Issues and actions ------------------------------------------------------------------

def action_id(code: str, item: str, step: str) -> str:
    """Return the action id of a remedy, distinct per finding, item and step

    The id is `doctor.<code>.<item>.<step>`; the item is the path the remedy acts on, so the same formula in two
    prefixes never shares an id.

    @param code  the finding's code
    @param item  the path the remedy acts on
    @param step  the remedy's step, such as `reinstall` or `rm`
    @returns     the action id
    """
    return f"doctor.{code}.{slug(item)}.{step}"


def _step(action: Action) -> str:
    """Return the step of a remedy, the last part of its action id

    @param action  the remedy
    @returns       the step, such as `reinstall`
    """
    return action.action_id.rsplit(".", 1)[-1]


def _steps(issue: Issue) -> set[str]:
    """Return the steps of the remedies that run; manual ones are only printed

    @param issue  the finding
    @returns      the steps of its remedies that are not manual
    """
    return {_step(a) for a in issue.remedies if not a.manual}


def _runs(remedies: Sequence[Action]) -> bool:
    """Return whether one of the remedies is a command that the tool runs

    @param remedies  the remedies of a finding
    @returns         False when every one of them is a note or a command for the user
    """
    return any(not a.manual for a in remedies)


def _each(paths: Sequence[str]) -> list[str]:
    """Return paths as evidence lines, for a finding whose first evidence line names only the first of them

    @param paths  the paths
    @returns      one line per path, cut at the evidence limit; none when that first line names them all
    """
    return limited(list(paths)) if len(paths) > NAMES_SHOWN else []


def _note(code: str, item: str, text: str, step: str = "note") -> Action:
    """Build a manual remedy, printed verbatim and never run

    @param code  the finding's code
    @param item  the path the remedy acts on, for the action id
    @param text  the text printed
    @param step  the step that ends the action id
    @returns     the action
    """
    return Action(action_id=action_id(code, item, step), kind="note", argv=[], sudo=False, description=text,
                  manual=True)


def _command(code: str, item: str, step: str, argv: list[str], description: str, *, sudo: bool = False,
             on_failure: OnFailure = OnFailure.STOP) -> Action:
    """Build a remedy command that is not a `brew` command, such as `rm` or `launchctl bootout`

    @param code         the finding's code
    @param item         the path the remedy acts on, for the action id
    @param step         the step that ends the action id
    @param argv         the program and its arguments, without `sudo`
    @param description  the text shown for the remedy
    @param sudo         run the command as root
    @param on_failure   what a failure of the command does
    @returns            the action
    """
    return Action(action_id=action_id(code, item, step), kind="command", argv=argv, sudo=sudo,
                  description=description, on_failure=on_failure)


def _issue(code: str, subject: str | None, brew: _Brew | None, evidence: Sequence[str],
           remedies: Sequence[Action] = (), *, title: str, auto_fix: bool = False,
           confirm_each: bool = False, repairs_install: bool = False) -> Issue:
    """Build a finding with its code's severity and blocked plan contexts

    @param code             the finding's code
    @param subject          the package, path or service it is about, or None
    @param brew             the instance it is about, or None for a host-wide finding
    @param evidence         the lines that show it
    @param remedies         the actions that fix it, in order
    @param title            a sentence that names what the finding is about
    @param auto_fix         `doctor --fix` applies it without a per-item prompt
    @param confirm_each     `doctor --fix` applies it after a per-item prompt
    @param repairs_install  apply phase 2 applies it when the subject is a plan target or its dependency
    @returns                the finding
    """
    return Issue(code=code, severity=SEVERITY[code], title=title, subject=subject,
                 instance_prefix=brew.prefix if brew else None, evidence=list(evidence), remedies=list(remedies),
                 auto_fix=auto_fix, confirm_each=confirm_each, repairs_install=repairs_install,
                 blocks=BLOCKS.get(code, ()))


def _skipped(code: str, brew: _Brew | None, what: str, why: str, subject: str | None = None) -> Issue:
    """Return an INFO finding for a check that did not run, so its silence never reads as a pass

    @param code     the code of the check
    @param brew     the instance the check could not judge, or None
    @param what     what the check would have told, as the words that follow `Not checked: `
    @param why      why the check did not run; each line of the text is one evidence line
    @param subject  what the check is about, or None
    @returns        the finding
    """
    return Issue(code=code, severity=Severity.INFO, title=NOT_CHECKED + what, subject=subject,
                 instance_prefix=brew.prefix if brew else None,
                 evidence=[line.strip() for line in why.splitlines() if line.strip()], remedies=[], auto_fix=False,
                 confirm_each=False, repairs_install=False, blocks=())


def _stash_actions(code: str, directory: str, run_dir) -> list[Action]:
    """Build the remedies that stash the local changes of a repository or tap and keep them as a run-directory patch

    The stash lives in `.git`, which phase 6 deletes; `-c` names the stash's author, because an `Action` carries no
    environment of its own.

    @param code       the finding's code
    @param directory  the repository or tap
    @param run_dir    the run directory; None gives the two commands for the user to run, with no patch file
    @returns          the stash, the patch and the command that brings the changes back
    """
    manual = run_dir is None
    identity = [arg for pair in STASH_IDENTITY for arg in ("-c", pair)]
    stash = Action(action_id=action_id(code, directory, "stash"), kind="command",
                   argv=[GIT] + identity + ["-C", directory, "stash", "push", "--include-untracked", "-m",
                                            "brew-ports" if manual else "brew-ports " + run_dir.run_id],
                   sudo=False, description="Set the changes aside", manual=manual)
    show = Action(action_id=action_id(code, directory, "patch"), kind="command",
                  argv=[GIT, "-C", directory, "stash", "show", "-p", "--include-untracked", "stash@{0}"],
                  sudo=False, description="Look at them", read_only=True, manual=manual,
                  dst=None if manual else os.path.join(run_dir.path, "data-archive", slug(directory) + ".stash.patch"))
    recover = Action(action_id=action_id(code, directory, "recover"), kind="command",
                     argv=[GIT, "-C", directory, "stash", "pop"], sudo=False,
                     description="To get the changes back afterwards", manual=True)
    if manual:
        return [stash, show, recover]
    return [_note(code, directory, offered("sets the changes aside with `git stash` and saves a copy of them in the "
                                           "run folder"), "offer"), stash, show, recover]


# Prefixes, repositories and the catalogue ---------------------------------------------

def _several_prefixes(ctx: _Scan) -> list[Issue]:
    """Report more than one Homebrew instance; every one other than a plan's target is a source

    @param ctx  the scan
    @returns    one finding, or none for a single instance
    """
    if len(ctx.brews) < 2:
        return []
    evidence = [f"{b.at}: {by_kind(p.kind for p in b.inv.packages) or 'no packages'}" for b in ctx.brews]
    target = locate.choose_target(ctx.bundle.result.instances, ctx.host_arch, None, ctx.environ)
    into = (f"`brew-ports plan --target brew` plans a move of every package of the other installations into "
            f"{at(target)}; `--target-prefix` names another Homebrew" if target is not None
            else "`brew-ports plan --target brew --target-prefix` with the folder of the Homebrew you keep plans a "
                 "move of every package of the other installations into it")
    note = _note("brew-several-prefixes", "host", f"Nothing to do. To merge them, {into}.")
    return [_issue("brew-several-prefixes", None, None, evidence, [note],
                   title=f"This Mac has {len(ctx.brews)} Homebrew installations")]


def _cannot_run(brew: _Brew, host_arch: str) -> Issue:
    """Report an installation whose `brew` is missing or fails, which stops a move into it

    @param brew       the installation
    @param host_arch  the host's architecture
    @returns          the finding, with the command that shows the user what Homebrew itself says
    """
    code = "brew-unusable-or-dirty"
    binary = brew.inst.binary or os.path.join(brew.prefix, "bin", "brew")
    detail = (brew.inst.usability_detail or "").strip().splitlines()
    if brew.inst.binary is None:
        fix = _note(code, binary, "Fix: install Homebrew there again, or leave it as it is and let a move delete it.")
    else:
        fix = actions.manual(brew.inst, action_id(code, binary, "manual"), ["config"],
                             "Fix: run it yourself and do what Homebrew asks for", host_arch)
    return _issue(code, binary, brew, detail[:1] or [f"`{binary} config` fails"],
                  [fix, _note(code, binary, MOVE_OUT % brew.prefix, "leaving")],
                  title=f"The `brew` command of {brew.at} cannot run")


def _unusable_or_dirty(ctx: _Scan) -> list[Issue]:
    """Report a `brew` that cannot run, or a repository whose lock-free `git status` is not empty

    @param ctx  the scan
    @returns    the findings, with a not-checked one for each repository whose `git status` failed
    """
    out: list[Issue] = []
    for b in ctx.brews:
        if not b.inst.drivable:
            out.append(_cannot_run(b, ctx.host_arch))
        repo = b.inst.repository or locate.repository_of(b.prefix)
        if not os.path.lexists(os.path.join(repo, ".git")):
            continue
        res = ctx.runner.run(inventory.git_status_probe(repo, f"0.brew.{slug(b.prefix)}.repository"))
        if res.exit != 0 or res.timed_out:
            out.append(_skipped("brew-unusable-or-dirty", b, f"whether Homebrew's own files in {repo} were changed",
                                locate.failure_text(res, "`git status`"), repo))
        elif res.stdout().strip():
            out.append(_dirty(ctx, "brew-unusable-or-dirty", b, repo, repo, status=res.stdout(),
                              title=f"Homebrew's own files in {repo} were changed"))
    return out


def _dirty(ctx: _Scan, code: str, brew: _Brew, subject: str, directory: str, *, status: str, title: str) -> Issue:
    """Report a repository or tap with local changes, with the remedies that stash them

    @param ctx        the scan
    @param code       the finding's code
    @param brew       the instance the repository belongs to
    @param subject    the finding's subject
    @param directory  the repository
    @param status     the output of `git status --porcelain`
    @param title      the finding's title
    @returns          the finding
    """
    files = [line.split(None, 1)[-1] for line in status.splitlines() if line.strip()]
    evidence = [f"`git status` lists {counted(len(files), 'changed file')}: {some(files)}",
                "`brew update` can fail over such changes"]
    remedies = _stash_actions(code, directory, ctx.runner.run_dir)
    return _issue(code, subject, brew, evidence, remedies, title=title, confirm_each=_runs(remedies))


def _stale_catalogue(ctx: _Scan) -> list[Issue]:
    """Report a missing per-arch API file, the tap-checkout fallback, or an API file older than 7 days

    @param ctx  the scan
    @returns    one finding per instance whose catalogue is missing, a fallback or stale
    """
    out: list[Issue] = []
    for b in ctx.brews:
        cat = b.cat
        api = os.path.join(b.inst.cache_dir or locate.default_cache_dir(ctx.environ), "api")
        evidence: list[str] = []
        if cat is None or cat.source in ("none", "names"):
            title = "Homebrew's package list is missing"
            if cat is not None and cat.load_error:
                evidence = [f"its file cannot be read: {cat.load_error}"]
            else:
                evidence = [f"there is no {os.path.join(api, 'internal', 'packages.*.jws.json')} for this Mac"]
            if cat is None or cat.source == "none":
                evidence.append("without it, brew-ports cannot tell which installed formulae and casks Homebrew has "
                                "stopped offering")
        elif cat.source == "taps":
            title = "Homebrew's package list is read from the homebrew/core tap, which says less about each package"
            evidence = ["it lacks web pages, the commands each formula provides, new names of renamed formulae and "
                        "which packages are prebuilt"]
            if cat.frozen:
                evidence.append("HOMEBREW_NO_INSTALL_FROM_API is set, so Homebrew does not download the full list")
        elif cat.api_mtime is not None and ctx.now - cat.api_mtime > STALE_S:
            title = f"Homebrew's package list is {int((ctx.now - cat.api_mtime) // 86400)} days old"
        else:
            continue
        if not b.inst.drivable:
            remedies = [b.no_fix("brew-stale-catalogue", api)]
        elif cat is not None and cat.source == "taps" and cat.frozen:
            remedies = [_note("brew-stale-catalogue", api, "Nothing to do if you set that variable on purpose.")]
        else:
            remedies = [actions.manual(b.inst, action_id("brew-stale-catalogue", api, "manual"), ["update"], "",
                                       ctx.host_arch),
                        _note("brew-stale-catalogue", api, "`brew-ports plan --target brew --refresh` runs it too, "
                              "for the Homebrew that packages move into.")]
        out.append(_issue("brew-stale-catalogue", (cat.api_file if cat is not None else None) or api, b, evidence,
                          remedies, title=title))
    return out


# Receipts and deleted formulae ---------------------------------------------------------

def _words(reason: Any) -> str:
    """Return Homebrew's reason for a deprecation as words: `repo_archived` reads `repo archived`

    @param reason  the `because` of a formula's `deprecate_args` or `disable_args`, a symbol or a sentence
    @returns       the reason with its underscores as spaces
    """
    return str(reason).replace("_", " ")


def _gone(brew: _Brew, pkg: Package) -> tuple[str, str | None] | None:
    """Return `(reason, replacement note or None)` when the catalogue does not know a core or tapless formula

    A formula that migrated to another tap counts as deleted, with that tap in the note. The reason is a clause
    about `it`, which ends a title or stands as an evidence line.

    @param brew  the formula's instance
    @param pkg   the installed formula
    @returns     the reason and the note; None when the catalogue knows the formula or cannot judge it
    """
    cat = brew.cat
    if cat is None or cat.source == "none" or pkg.origin not in ("", CORE_TAP):
        return None
    names = brew.names(pkg)
    if any(cat.knows(n) or cat.renamed_to(n) for n in names):
        return None
    for name in names:
        home = cat.tap_migration(name)
        if home:
            return (f"Homebrew moved it to the tap {home}",
                    f"Fix: install {name} from the tap {home}, then uninstall this copy. {MOVE_FINDS_IT}")
    return "Homebrew's package list does not have it under any name", None


def _trusted(brew: _Brew, pkg: Package) -> bool:
    """Return whether a deleted-formula verdict holds

    Only the API catalogue knows renames, so under a fallback Homebrew's `check_deleted_formula` must list the
    formula too.

    @param brew  the formula's instance
    @param pkg   the formula
    @returns     True under the API catalogue, or when `brew doctor` lists the formula
    """
    cat = brew.cat
    return (cat is not None and cat.source == "api") or bool(brew.quote("check_deleted_formula", brew.names(pkg)))


def _unavailable(brew: _Brew, pkg: Package) -> tuple[str, str | None] | None:
    """Return `(reason, replacement note)` when `brew reinstall` cannot bring a formula back; else None

    The formula is deleted, or Homebrew refuses to install it.

    @param brew  the formula's instance
    @param pkg   the formula
    @returns     the reason and the note, which may be None; None when a reinstall can work
    """
    gone = _gone(brew, pkg)
    if gone is not None and _trusted(brew, pkg):
        return gone
    refused = brew.cat.refused(pkg.name) if brew.cat is not None else None
    if not refused:
        return None
    replacement = refused.get("replacement_formula") or refused.get("replacement_cask")
    note = (f"Fix: install {replacement}, which Homebrew names as its replacement, then uninstall {pkg.name}. "
            f"{MOVE_FINDS_IT}") if replacement else None
    since = f" on {refused['date']}" if refused.get("date") else ""
    why = f" ({_words(refused['because'])})" if refused.get("because") else ""
    return f"Homebrew stopped installing it{since}{why}", note


def _data_ties(ctx: _Scan, brew: _Brew, pkg: Package) -> str:
    """Describe the owned services and data directories of a formula

    @param ctx   the scan
    @param brew  the formula's instance
    @param pkg   the formula
    @returns     the services and directories as one phrase; empty when there are none
    """
    names = brew.names(pkg)
    labels: list[str] = []
    dirs: list[str] = []
    for svc in ctx.services:
        if (svc.owned and svc.instance_prefix == brew.prefix and svc.package_kind == "formula"
                and svc.package in names):
            labels.append(svc.label)
            dirs.extend(d for d in svc.data_dirs if d not in dirs)
    for name in names:
        dirs.extend(d for d in env_services.data_dirs(brew.prefix, name, ()) if d not in dirs)
    return series([f"the service {label}" for label in labels] + [f"the data folder {d}" for d in dirs])


def _removal_rule(ctx: _Scan, brew: _Brew, pkg: Package, code: str, replacement: str | None) -> list[Action]:
    """Return the remedies of a deleted or refused formula: its uninstall, or a note of why there is none

    A known replacement gets a note; a formula that owns a service or a data directory is not removed, because
    only its binaries can read that data and no catalogue reinstalls them.

    @param ctx          the scan
    @param brew         the formula's instance
    @param pkg          the deleted formula, or one Homebrew refuses to install
    @param code         the finding's code
    @param replacement  the text of the replacement note, or None
    @returns            the remedies; only an uninstall is a command that runs
    """
    rack = brew.racks(pkg)[0]
    if replacement:
        return [_note(code, rack, replacement)]
    ties = _data_ties(ctx, brew, pkg)
    if ties:
        return [_note(code, rack, f"brew-ports offers no fix: {pkg.name} owns {ties}. Only its own programs can "
                      "read that data, and Homebrew cannot install them again.")]
    if not brew.inst.drivable:
        return [brew.no_fix(code, rack)]
    return [actions.uninstall_formulae(brew.inst, ctx.host_arch, action_id(code, rack, "uninstall"), [pkg.name],
                                       on_failure=OnFailure.STOP)]


def _receiptless(brew: _Brew, pkg: Package) -> list[str]:
    """Return the kegs of a formula that have no `INSTALL_RECEIPT.json`

    @param brew  the formula's instance
    @param pkg   the formula
    @returns     the keg directories, in the inventory's order
    """
    missing = set(brew.inv.receiptless_kegs)
    return [keg for keg in brew.inv.kegs.get(pkg.name) or [] if keg in missing]


def _keg_without_receipt(ctx: _Scan) -> list[Issue]:
    """Report the kegs without `INSTALL_RECEIPT.json`, one finding per formula

    @param ctx  the scan
    @returns    the findings
    """
    out: list[Issue] = []
    for b in ctx.brews:
        for pkg in b.packages("formula"):
            kegs = _receiptless(b, pkg)
            if kegs:
                out.append(_receiptless_issue(ctx, b, pkg, kegs))
    return out


def _receiptless_issue(ctx: _Scan, brew: _Brew, pkg: Package, kegs: list[str]) -> Issue:
    """Build the finding of a receipt-less formula: `brew reinstall <f>`, then `brew tab --installed-on-request <f>`

    A formula that `brew reinstall` cannot bring back gets the removal rule; the tab step, left out for a known
    dependency, undoes the `installed_on_request: false` that `reinstall` copies from the missing receipt.

    @param ctx   the scan
    @param brew  the formula's instance
    @param pkg   the formula
    @param kegs  its kegs without a receipt
    @returns     the finding
    """
    code = "brew-keg-without-receipt"
    title = f"{pkg.name} has no install record"
    evidence = [f"INSTALL_RECEIPT.json, where Homebrew records how it installed a version, is missing from "
                f"{series(kegs)}", "without it, brew-ports cannot tell whether you installed it yourself"]
    rack = brew.racks(pkg)[0]
    gone = _unavailable(brew, pkg)
    if gone is not None:
        reason, replacement = gone
        remedies = _removal_rule(ctx, brew, pkg, code, replacement)
        return _issue(code, pkg.name, brew, evidence + [reason], remedies, title=title, confirm_each=_runs(remedies))
    if not brew.inst.drivable:
        return _issue(code, pkg.name, brew, evidence, [brew.no_fix(code, rack)], title=title)
    remedies = [actions.reinstall(brew.inst, ctx.host_arch, action_id(code, rack, "reinstall"), [pkg.name])]
    if pkg.requested is not False:
        remedies.append(actions.tab_installed_on_request(brew.inst, ctx.host_arch, action_id(code, rack, "tab"),
                                                         [pkg.name]))
    return _issue(code, pkg.name, brew, evidence, remedies, title=title, confirm_each=True, repairs_install=True)


def _deleted_formula(ctx: _Scan) -> list[Issue]:
    """Report a keg of a deleted formula, unless the receipt-less keg's finding already applies the removal rule

    @param ctx  the scan
    @returns    the findings
    """
    out: list[Issue] = []
    for b in ctx.brews:
        if b.cat is None:
            continue
        for pkg in b.packages("formula"):
            gone = _gone(b, pkg)
            if gone is None or (_receiptless(b, pkg) and _unavailable(b, pkg) is not None):
                continue
            reason, replacement = gone
            evidence = b.quote("check_deleted_formula", b.names(pkg))
            if _trusted(b, pkg):
                remedies = _removal_rule(ctx, b, pkg, "brew-deleted-formula", replacement)
                if replacement is None:
                    evidence.insert(0, "Homebrew can neither upgrade it nor install it again")
                if _runs(remedies):
                    remedies.append(_note("brew-deleted-formula", b.racks(pkg)[0], "Leave it if you still use it.",
                                          "keep"))
            else:
                remedies = [_note("brew-deleted-formula", b.racks(pkg)[0], "brew-ports offers no fix: the package "
                                  f"list read here does not record new names, so {pkg.name} may only have been "
                                  "renamed, and `brew doctor` does not report it.")]
            out.append(_issue("brew-deleted-formula", pkg.name, b, evidence, remedies,
                              title=f"{pkg.name} is installed, but {reason}", confirm_each=_runs(remedies)))
    return out


# Formula states and kegs -----------------------------------------------------------------

def _lifecycle(cat: Catalogue | None, pkg: Package) -> list[str]:
    """Describe the dates, reasons and replacements of a formula's `deprecate_args` and `disable_args`

    @param cat  the instance's catalogue, or None
    @param pkg  the installed formula
    @returns    one line for each of the two that the entry has
    """
    entry = cat.formula(pkg.name) if cat is not None else None
    out: list[str] = []
    words = {"deprecate_args": "deprecated", "disable_args": "disabled" if pkg.disabled else "to be disabled"}
    for key, word in words.items():
        args = plain_keys(entry.get(key)) if entry and isinstance(entry.get(key), dict) else None
        if not args:
            continue
        text = word + (f" on {args['date']}" if args.get("date") else "")
        if args.get("because"):
            text += f" ({_words(plain_symbol(args['because']))})"
        replacement = args.get("replacement_formula") or args.get("replacement_cask")
        if replacement:
            text += f"; Homebrew suggests {replacement} instead"
        out.append(text)
    return out


def _deprecated_formula(ctx: _Scan) -> list[Issue]:
    """Report a deprecated or disabled formula, with its replacement names

    @param ctx  the scan
    @returns    the findings
    """
    code = "brew-deprecated-formula"
    out: list[Issue] = []
    for b in ctx.brews:
        for pkg in b.packages("formula"):
            if pkg.deprecated or pkg.disabled:
                title = (f"{pkg.name} is disabled: Homebrew does not install it any more" if pkg.disabled
                         else f"{pkg.name} is deprecated: Homebrew plans to stop offering it")
                evidence = _lifecycle(b.cat, pkg) + b.quote("check_deprecated_disabled", b.names(pkg))
                note = _note(code, b.racks(pkg)[0], "Nothing to do for a formula that still works for you.")
                out.append(_issue(code, pkg.name, b, evidence, [note], title=title))
    return out


def _unlinked_keg(ctx: _Scan) -> list[Issue]:
    """Report a formula neither linked nor keg-only, with `brew link <f>` and the dry run that lists conflicts

    @param ctx  the scan
    @returns    the findings
    """
    code = "brew-unlinked-keg"
    out: list[Issue] = []
    for b in ctx.brews:
        for pkg in b.packages("formula"):
            if pkg.linked or pkg.keg_only:
                continue
            title = f"{pkg.name} is installed, but not linked into {b.prefix}"
            evidence = [f"its commands are not in {b.prefix}/bin, and its libraries not in {b.prefix}/lib"]
            evidence += b.quote("check_for_unlinked_but_not_keg_only", b.names(pkg))
            rack = b.racks(pkg)[0]
            if not b.inst.drivable:
                out.append(_issue(code, pkg.name, b, evidence, [b.no_fix(code, rack)], title=title))
                continue
            remedies = [actions.link(b.inst, ctx.host_arch, action_id(code, rack, "link"), pkg.name),
                        actions.manual(b.inst, action_id(code, rack, "manual"),
                                       ["link", "--overwrite", "--dry-run", pkg.name],
                                       "If `brew link` reports conflicting files, list them", ctx.host_arch),
                        _note(code, rack, "A move into this Homebrew links it when a replacement needs it.")]
            out.append(_issue(code, pkg.name, b, evidence, remedies, title=title, repairs_install=True))
    return out


def _broken_links(prefix: str) -> list[tuple[str, str]]:
    """Return `(link, target text)` of every dangling symlink below the prefix's `LINK_DIRS`

    Symlinked directories are not followed.

    @param prefix  the Homebrew prefix
    @returns       the pairs, sorted
    """
    out: set[tuple[str, str]] = set()
    for sub in LINK_DIRS:
        top = os.path.join(prefix, sub)
        if os.path.islink(top) or not os.path.isdir(top):
            continue
        for dirpath, dirnames, filenames in os.walk(top):
            for name in dirnames + filenames:
                path = os.path.join(dirpath, name)
                if os.path.islink(path) and not os.path.exists(path):
                    try:
                        out.add((path, os.readlink(path)))
                    except OSError:
                        continue
    return sorted(out)


def _homebrew_link(inst: model.Instance, link: str, target: str) -> bool:
    """Return whether a link is Homebrew's to remove

    Its prefix is a dedicated one, or the link or its target lies in the instance's `owned_roots`, as other
    installers share `/usr/local`.

    @param inst    the Homebrew instance
    @param link    the dangling symlink
    @param target  the link's text
    @returns       True when the link is Homebrew's
    """
    roots = tuple(inst.owned_roots) or (inst.prefix,)
    if roots == (inst.prefix,):
        return True
    fold = env.fold_case_for(inst)
    resolved = os.path.normpath(os.path.join(os.path.dirname(link), target))
    return system.text_names_prefix(link, roots, fold) or system.text_names_prefix(resolved, roots, fold)


def _broken_symlink(ctx: _Scan) -> list[Issue]:
    """Report the broken symlinks in the prefix, each of Homebrew's own with `rm <symlink>`

    @param ctx  the scan
    @returns    the findings
    """
    code = "brew-broken-symlink"
    out: list[Issue] = []
    for b in ctx.brews:
        for link, target in _broken_links(b.prefix):
            title = f"The link {link} points at a file that is gone"
            evidence = [f"it points at {target}"] + b.quote("check_for_broken_symlinks", [link])
            if not _homebrew_link(b.inst, link, target):
                note = _note(code, link, f"brew-ports leaves it alone: it lies outside Homebrew's own folders in "
                             f"{b.prefix}, so something else may have put it there.")
                out.append(_issue(code, link, b, evidence, [note], title=title))
                continue
            rm = _command(code, link, "rm", [RM, link], f"delete the broken link {link}", on_failure=OnFailure.PROBE)
            out.append(_issue(code, link, b, evidence, [rm], title=title, confirm_each=True))
    return out


def _link_targets(brew: _Brew, names: Sequence[str], *parts: str) -> list[str]:
    """Return the realpaths of a formula's directory links under one directory of the prefix

    @param brew   the formula's instance
    @param names  the formula's names
    @param parts  the directory's path components under the prefix, such as `opt`
    @returns      the realpath of each name's link that points at a directory
    """
    out = []
    for name in names:
        link = os.path.join(brew.prefix, *(parts + (name,)))
        if os.path.islink(link) and os.path.isdir(link):
            out.append(os.path.realpath(link))
    return out


def _kept_kegs(brew: _Brew, pkg: Package, kegs: Sequence[str]) -> dict[str, str]:
    """Map each keg that stays to why: the linked keg and the `opt` link's target, else the newest keg

    A keg-only formula has no linked keg; one keg always stays.

    @param brew  the formula's instance
    @param pkg   the formula
    @param kegs  its keg directories, newest last
    @returns     each kept keg's reason
    """
    real = {os.path.realpath(k): k for k in kegs}
    names = brew.names(pkg)
    kept: dict[str, str] = {}
    for reason, parts in (("linked", ("var", "homebrew", "linked")), ("the version other formulae use", ("opt",))):
        for target in _link_targets(brew, names, *parts):
            if target in real:
                keg = real[target]
                kept[keg] = kept[keg] + " and " + reason if keg in kept else reason
    if not kept and kegs:
        kept[kegs[-1]] = "the newest"
    return kept


def _keg_in_use(ctx: _Scan, brew: _Brew, keg: str) -> str | None:
    """Say why a keg must stay, or None

    Root-owned paths below it stop a removal as the user part-way, and a service may run its program from it.

    @param ctx   the scan
    @param brew  the keg's instance
    @param keg   the keg directory
    @returns     the reason, or None
    """
    root = os.path.realpath(keg)
    for paths in brew.inv.root_owned.values():
        if any(p == keg or p.startswith(keg + os.sep) for p in paths):
            return "files in it belong to root"
    for svc in ctx.services:
        program = os.path.realpath(svc.program) if svc.program else None
        if svc.instance_prefix == brew.prefix and program and (program == root or program.startswith(root + os.sep)):
            return f"the service {svc.label} runs {svc.program} from it"
    return None


def _several_versions(ctx: _Scan) -> list[Issue]:
    """Report each extra keg of a formula with `rm -rf <keg>`

    A pinned formula, or kegs that must stay, get no remedy.

    @param ctx  the scan
    @returns    one finding per removable keg, else one per formula
    """
    code = "brew-several-versions"
    out: list[Issue] = []
    for b in ctx.brews:
        for pkg in b.packages("formula"):
            kegs = list(b.inv.kegs.get(pkg.name) or [])
            if len(kegs) < 2:
                continue
            title = f"{pkg.name} has {len(kegs)} versions installed: {', '.join(os.path.basename(k) for k in kegs)}"
            rack = b.racks(pkg)[0]
            if pkg.pinned:
                note = _note(code, rack, f"Nothing to do: {pkg.name} is pinned, so every version stays.")
                out.append(_issue(code, pkg.name, b, [], [note], title=title))
                continue
            kept = _kept_kegs(b, pkg, kegs)
            evidence = ["in use: " + ", ".join(f"{os.path.basename(k)} ({why})" for k, why in kept.items())]
            removable = []
            for keg in kegs:
                why = None if keg in kept else _keg_in_use(ctx, b, keg)
                if why:
                    evidence.append(f"{os.path.basename(keg)} stays too: {why}")
                elif keg not in kept:
                    removable.append(keg)
            if not removable:
                note = _note(code, rack, "Nothing to do: every version stays.")
                out.append(_issue(code, pkg.name, b, evidence, [note], title=title))
            for keg in removable:
                rm = _command(code, keg, "rm", [RM, "-rf", keg], f"delete the unused version {keg}")
                out.append(_issue(code, keg, b, evidence, [rm], confirm_each=True,
                                  title=f"Version {os.path.basename(keg)} of {pkg.name} is installed but not in "
                                        "use"))
    return out


# Dependencies, linkage, outdated and pinned formulae ------------------------------------

def _json_skipped(brew: _Brew, probe: str) -> str | None:
    """Say why a check fed by the inventory probes did not run, or None

    @param brew   the instance
    @param probe  the `brew` command the check reads, such as `brew missing`
    @returns      the reason, or None when the probes ran
    """
    if not brew.inst.drivable:
        return brew.cannot_run()
    if not brew.inv.used_json:
        return f"`brew info` failed there, so `{probe}` was not run"
    return None


def _install(ctx: _Scan, brew: _Brew, dep: str) -> Action:
    """Build the `brew install <dep>` of a missing dependency: `--cask` for a cask, printed when it needs sudo

    @param ctx   the scan
    @param brew  the instance
    @param dep   the dependency, tap-qualified or not
    @returns     the action
    """
    code = "brew-missing-dependency"
    short = dep.rsplit("/", 1)[-1]
    cat = brew.cat
    if cat is not None and not cat.knows(short) and cat.knows(short, "cask"):
        room = os.path.join(brew.prefix, "Caskroom", short)
        info = cat.cask(short)
        if info is not None and info.privileged_install:
            return actions.manual(brew.inst, action_id(code, room, "manual"), ["install", "--cask", dep],
                                  "Fix: this cask asks for your password, so run it yourself", ctx.host_arch)
        return actions.install_casks(brew.inst, ctx.host_arch, action_id(code, room, "install"), [dep],
                                     on_failure=OnFailure.STOP)
    # --as-dependency: a plain install would record the dependency as installed on
    # request, and every later plan would count it as a root the user chose.
    return actions.install_formulae(brew.inst, ctx.host_arch,
                                    action_id(code, os.path.join(brew.prefix, "Cellar", short), "install"), [dep],
                                    as_dependency=True, on_failure=OnFailure.STOP)


def _missing_dependency(ctx: _Scan) -> list[Issue]:
    """Report each dependency `brew missing` lists, with `brew install <dep>`

    @param ctx  the scan
    @returns    the findings, or a not-checked one where `brew missing` did not run
    """
    out: list[Issue] = []
    for b in ctx.brews:
        skipped = _json_skipped(b, "brew missing")
        if skipped is None and "brew missing" in (b.inv.inventory_error or ""):
            skipped = b.inv.inventory_error
        if skipped:
            out.append(_skipped("brew-missing-dependency", b, "whether an installed formula lacks a dependency",
                                skipped))
            continue
        needed: dict[str, list[str]] = {}
        for name, deps in sorted(b.inv.missing.items()):
            for dep in deps:
                needed.setdefault(dep, []).append(name)
        for dep, users in sorted(needed.items()):
            named = [user for user in users if user]
            who = series(named) if len(named) <= NAMES_SHOWN else some(named)
            title = (f"{who} {'needs' if len(named) == 1 else 'need'} {dep}, which is not installed" if named
                     else f"{dep} is a dependency that is not installed")
            remedy = _install(ctx, b, dep)
            out.append(_issue("brew-missing-dependency", dep, b, ["`brew missing` reports it"], [remedy],
                              title=title, auto_fix=not remedy.manual, repairs_install=not remedy.manual))
    return out


def _broken_linkage(ctx: _Scan) -> list[Issue]:
    """Report a keg with `missing`, `other` or `usrlocal` references in its binaries, with `brew reinstall <f>`

    @param ctx  the scan
    @returns    the findings
    """
    code = "brew-broken-linkage"
    linkage = ctx.bundle.result.linkage
    reports = linkage.get("packages") or {}
    binaries = linkage.get("binaries") or {}
    out: list[Issue] = []
    for b in ctx.brews:
        for pkg in b.packages("formula"):
            broken = (reports.get(env_linkage.package_key(pkg)) or {}).get("broken") or []
            if not broken:
                continue
            title = f"{pkg.name} loads libraries that are missing or lie outside this Homebrew"
            evidence = limited([f"{path} {LOADS[ref['class']] % ref.get('name')}"
                                for path in broken for ref in (binaries.get(path) or {}).get("references") or []
                                if ref.get("class") in env_linkage.BROKEN])
            rack = b.racks(pkg)[0]
            if not b.inst.drivable:
                out.append(_issue(code, pkg.name, b, evidence, [b.no_fix(code, rack)], title=title))
                continue
            reinstall = actions.reinstall(b.inst, ctx.host_arch, action_id(code, rack, "reinstall"), [pkg.name])
            out.append(_issue(code, pkg.name, b, evidence, [reinstall], title=title, confirm_each=True,
                              repairs_install=True))
    return out


def _outdated_keg(ctx: _Scan) -> list[Issue]:
    """Report outdated formulae and casks; `brew upgrade` is only suggested, as a plan upgrades its targets itself

    @param ctx  the scan
    @returns    the findings, or a not-checked one where the inventory probes did not run
    """
    code = "brew-outdated-keg"
    out: list[Issue] = []
    for b in ctx.brews:
        skipped = _json_skipped(b, "brew outdated")
        if skipped:
            out.append(_skipped(code, b, "which packages have a newer version", skipped))
            continue
        for kind, current in (("formula", b.inv.outdated_formulae), ("cask", b.inv.outdated_casks)):
            for pkg in b.packages(kind):
                if not pkg.outdated:
                    continue
                version = current.get(pkg.name)
                title = f"{pkg.name} has a newer version" + (f", {version}" if version else "")
                item = os.path.join(b.prefix, "Cellar" if kind == "formula" else "Caskroom", pkg.name)
                remedies = [_note(code, item, "Nothing to do before a move: a move into this Homebrew upgrades what "
                                  "it needs by itself."),
                            actions.manual(b.inst, action_id(code, item, "manual"),
                                           ["upgrade", "--" + kind, pkg.name], "To upgrade it yourself",
                                           ctx.host_arch)]
                out.append(_issue(code, pkg.name, b, [f"installed: {pkg.version}"] if pkg.version else [], remedies,
                                  title=title))
    return out


def _pinned_formula(ctx: _Scan) -> list[Issue]:
    """Report a pinned formula: a pinned outdated dependency of a plan's target stops that plan

    @param ctx  the scan
    @returns    the findings
    """
    code = "brew-pinned-formula"
    out: list[Issue] = []
    for b in ctx.brews:
        for pkg in b.packages("formula"):
            if pkg.pinned:
                note = _note(code, b.racks(pkg)[0], "Nothing to do. A move that needs a newer version of a pinned "
                             "formula stops until you run `brew unpin` for it.")
                out.append(_issue(code, pkg.name, b, ["a newer version exists"] if pkg.outdated else [], [note],
                                  title=f"{pkg.name} is pinned: Homebrew does not upgrade it"))
    return out


# Taps, permissions, services and casks -----------------------------------------------

def _dirty_tap(ctx: _Scan) -> list[Issue]:
    """Report a tap with its own `.git` whose `git status` is not empty, with the stash commands

    @param ctx  the scan
    @returns    the findings, with a not-checked one for each tap whose `git status` failed
    """
    code = "brew-dirty-tap"
    out: list[Issue] = []
    for b in ctx.brews:
        for tap in b.inv.taps:
            if tap.dirty:
                out.append(_dirty(ctx, code, b, tap.name, tap.path, status=tap.status,
                                  title=f"The files of the tap {tap.name} were changed"))
            elif tap.has_git and tap.dirty is None and tap.error:
                out.append(_skipped(code, b, f"whether the files of the tap {tap.name} were changed", tap.error,
                                    tap.name))
    return out


def _unwritable_prefix(ctx: _Scan) -> list[Issue]:
    """Report the `WRITABLE_DIRS` of a prefix that the user cannot write, with a manual `chown`

    It blocks `UNINSTALL` too: `brew uninstall` unlinks a keg directory by directory and stops at the first one it
    cannot write.

    @param ctx  the scan
    @returns    the findings
    """
    out: list[Issue] = []
    for b in ctx.brews:
        bad = [d for d in (os.path.join(b.prefix, sub) for sub in WRITABLE_DIRS)
               if os.path.isdir(d) and not os.access(d, os.W_OK)]
        if bad:
            note = _note("brew-unwritable-prefix", b.prefix,
                         f"Fix: sudo chown -R \"$(whoami)\" {' '.join(shlex.quote(d) for d in bad)}")
            out.append(_issue("brew-unwritable-prefix", b.prefix, b, [f"not writable: {', '.join(bad)}"], [note],
                              title=f"You cannot write to {counted(len(bad), 'folder')} of {b.at}, so `brew` can "
                                    "neither install nor uninstall there"))
    return out


def _installed_names(brew: _Brew) -> set[str]:
    """Return every name an installed formula of the instance goes by, its racks' names included

    @param brew  the instance
    @returns     the names
    """
    names: set[str] = set()
    for pkg in brew.packages("formula"):
        names.update(brew.names(pkg))
    return names


def _orphan_service(ctx: _Scan) -> list[Issue]:
    """Report an owned plist of the instance whose formula is not installed there

    The remedies are `launchctl bootout` in the recorded domain when the job is loaded, then `rm <plist>`.

    @param ctx  the scan
    @returns    the findings
    """
    code = "brew-orphan-service"
    out: list[Issue] = []
    for b in ctx.brews:
        installed = _installed_names(b)
        for svc in ctx.services:
            if not (svc.owned and svc.package and svc.package_kind == "formula" and svc.instance_prefix == b.prefix):
                continue
            canon = b.cat.canonical(svc.package) if b.cat is not None else None
            if svc.package in installed or (canon and canon in installed):
                continue
            evidence = [f"its file is {tilde(svc.plist, ctx.home)}"]
            remedies = []
            if svc.loaded and svc.domain:
                evidence.append("it is still loaded" + (f", and runs as process {svc.pid}" if svc.pid else ""))
                remedies.append(_command(code, svc.plist, "bootout",
                                         [LAUNCHCTL, "bootout", f"{svc.domain}/{svc.label}"],
                                         f"unload the service {svc.label}", sudo=svc.domain == "system",
                                         on_failure=OnFailure.PROBE))
            remedies.append(_command(code, svc.plist, "rm", [RM, svc.plist], f"delete the service file {svc.plist}",
                                     sudo=svc.scope == "system", on_failure=OnFailure.PROBE))
            out.append(_issue(code, svc.label, b, evidence, remedies, confirm_each=True,
                              title=f"The service {svc.label} is left over from {svc.package}, which is not "
                                    "installed"))
    return out


def _caskroom(brew: _Brew, pkg: Package) -> str | None:
    """Return a cask's Caskroom directory when it is a real directory

    @param brew  the cask's instance
    @param pkg   the cask
    @returns     `<prefix>/Caskroom/<token>`, or None when it is missing or a symlink
    """
    room = os.path.join(brew.prefix, "Caskroom", pkg.name)
    return room if os.path.isdir(room) and not os.path.islink(room) else None


def _app_targets(ctx: _Scan, brew: _Brew, pkg: Package, room: str) -> list[str] | None:
    """Return where the installed version's `app` artifacts lie, as a record of that version names them

    The record is the receipt, else the installed caskfile in a JSON form, else the catalogue when it describes the
    installed version; a cask the catalogue does not know has none. The app directory comes from
    `.metadata/config.json`, else `HOMEBREW_CASK_OPTS`, else `/Applications`.

    @param ctx   the scan
    @param brew  the cask's instance
    @param pkg   the cask
    @param room  the cask's Caskroom directory
    @returns     the app bundle paths; None when only the catalogue names them and it describes another version
    """
    receipt = inventory.read_json(os.path.join(room, ".metadata", inventory.RECEIPT))
    config = inventory.read_json(os.path.join(room, ".metadata", "config.json"))
    dirs = dirs_from_config(config, cask_dirs(brew.prefix, ctx.environ, brew.inv.brew_env, ctx.home))
    artifacts: list[Artifact] | None
    if receipt is not None and isinstance(receipt.get("uninstall_artifacts"), list):
        artifacts = normalise_artifacts(receipt["uninstall_artifacts"])
    else:
        artifacts = _caskfile_artifacts(room, pkg.name)
    if artifacts is None:
        info = brew.cat.cask(pkg.name) if brew.cat is not None else None
        if info is not None and info.version != pkg.version:
            return None
        artifacts = info.artifacts if info is not None else []
    return [target for art in artifacts if art.kind == "app"
            for target in artifact_targets(art, dirs, brew.prefix, ctx.home)]


def _missing_app(ctx: _Scan) -> list[Issue]:
    """Report an installed cask whose `app` is absent, with `brew reinstall --cask <t>`

    The reinstall is only printed when the cask needs sudo to install or uninstall. A cask whose apps only the
    catalogue names, for another version than the installed one, gets a not-checked finding.

    @param ctx  the scan
    @returns    the findings
    """
    code = "brew-missing-app"
    out: list[Issue] = []
    for b in ctx.brews:
        for pkg in b.packages("cask"):
            room = _caskroom(b, pkg)
            if room is None:
                continue
            targets = _app_targets(ctx, b, pkg, room)
            if targets is None:
                current = b.cat.version(pkg.name, "cask") if b.cat is not None else None
                out.append(_skipped(code, b, f"whether the app of the cask {pkg.name} is in place",
                                    f"Homebrew kept no record of what {pkg.name} {pkg.version or ''} installed, and "
                                    f"its package list describes {'version ' + current if current else 'another one'}",
                                    pkg.name))
                continue
            missing = [t for t in targets if not os.path.lexists(t)]
            if not missing:
                continue
            title = (f"The {'app' if len(missing) == 1 else 'apps'} of the cask {pkg.name} "
                     f"{'is' if len(missing) == 1 else 'are'} missing: {', '.join(missing)}")
            if not b.inst.drivable:
                out.append(_issue(code, pkg.name, b, [], [b.no_fix(code, room)], title=title))
            elif pkg.privileged_install or pkg.privileged_uninstall:
                manual = actions.manual(b.inst, action_id(code, room, "manual"), ["reinstall", "--cask", pkg.name],
                                        "Fix: this cask asks for your password, so run it yourself", ctx.host_arch)
                out.append(_issue(code, pkg.name, b, [], [manual], title=title))
            else:
                reinstall = actions.reinstall(b.inst, ctx.host_arch, action_id(code, room, "reinstall"), [pkg.name],
                                              kind="cask")
                out.append(_issue(code, pkg.name, b, [], [reinstall], title=title, confirm_each=True))
    return out


def _tap_provides_cask(brew: _Brew, token: str) -> bool:
    """Return whether `<repository>/Library/Taps/*/*/Casks/**/<token>.rb` exists

    @param brew   the instance
    @param token  the cask token
    @returns      True when a tap checkout defines the cask
    """
    taps = os.path.join(brew.inst.repository or locate.repository_of(brew.prefix), "Library", "Taps")
    pattern = os.path.join(glob.escape(taps), "*", "*", "Casks", "**", glob.escape(token) + ".rb")
    return bool(glob.glob(pattern, recursive=True))


def _installed_caskfile(room: str, token: str) -> str | None:
    """Return the Caskroom copy of the cask that Homebrew loads it from, so `brew info --installed` lists it

    The copy is `.metadata/<version>/<timestamp>/Casks/<token>.<extension>` under the newest timestamp, the first
    extension of `CASKFILE_EXTENSIONS` that exists.

    @param room   the cask's Caskroom directory
    @param token  the cask token
    @returns      the cask file; None when the newest timestamp holds none
    """
    stamps = glob.glob(os.path.join(glob.escape(room), ".metadata", "*", "*"))
    if not stamps:
        return None
    newest = max(stamps, key=os.path.basename)
    files = (os.path.join(newest, "Casks", f"{token}.{ext}") for ext in CASKFILE_EXTENSIONS)
    return next((path for path in files if os.path.isfile(path)), None)


def _caskfile_artifacts(room: str, token: str) -> list[Artifact] | None:
    """Return the artifacts the installed caskfile records, when it is a JSON form that records them

    A `<token>.json` lists them as `brew info` does, a legacy `<token>.internal.json` as the API's `raw_artifacts`;
    Homebrew's compact `<token>.json` lists them only for a cask with nothing to uninstall, as an empty list.

    @param room   the cask's Caskroom directory
    @param token  the cask token
    @returns      the artifacts; None for a Ruby caskfile, none at all, or a JSON one that lists none
    """
    path = _installed_caskfile(room, token)
    data = inventory.read_json(path) if path is not None and path.endswith(".json") else None
    for key in ("artifacts", "raw_artifacts"):
        if data is not None and isinstance(data.get(key), list):
            return normalise_artifacts(data[key])
    return None


def _drop_cask_record(ctx: _Scan, room: str) -> list[Action]:
    """Build the remedies that archive an orphan Caskroom record into the run directory, then remove it as its owner

    `brew uninstall --cask --force` exits 0 without removing a cask it cannot load, because `--force` hides the
    `CaskUnavailableError`; the artifacts the cask installed stay, as a note says.

    @param ctx   the scan
    @param room  the orphan Caskroom directory
    @returns     the archive, the removal and the note; without a run directory, the removal for the user to run
    """
    code = "brew-orphan-caskroom"
    run_dir = ctx.runner.run_dir
    note = _note(code, room, "The apps and files that the cask installed stay: move them to the Trash yourself if "
                 "you do not want them.", "note")
    if run_dir is None:
        return [Action(action_id=action_id(code, room, "rm"), kind="command", argv=[RM, "-rf", room], sudo=False,
                       description="", manual=True), note]
    dst = os.path.join(run_dir.path, "backup", "caskroom", slug(room) + ".tar.gz")
    archive = Action(action_id=action_id(code, room, "tar"), kind="command",
                     argv=[TAR, "-czf", "-", "-C", os.path.dirname(room), os.path.basename(room)], sudo=False,
                     description=f"save Homebrew's record of the cask as {dst}", dst=dst)
    remove = Action(action_id=action_id(code, room, "rm"), kind="command", argv=[RM, "-rf", room], sudo=False,
                    description=f"delete Homebrew's record of the cask, {room}")
    offer = _note(code, room, offered("saves Homebrew's record of the cask in the run folder, then deletes it"),
                  "offer")
    return [offer, archive, remove, note]


def _orphan_caskroom(ctx: _Scan) -> list[Issue]:
    """Report a Caskroom directory that no catalogue entry, rename, tap or installed cask file defines

    Without a catalogue the check is skipped, and `brew-stale-catalogue` says so.

    @param ctx  the scan
    @returns    the findings
    """
    out: list[Issue] = []
    for b in ctx.brews:
        cat = b.cat
        if cat is None or cat.source == "none":
            continue
        for pkg in b.packages("cask"):
            room = _caskroom(b, pkg)
            token = pkg.name
            if (room is None or cat.knows(token, "cask") or cat.renamed_to(token, "cask")
                    or _tap_provides_cask(b, token) or _installed_caskfile(room, token)):
                continue
            evidence = ["neither a tap nor Homebrew's own copy of the cask says what it is, so `brew uninstall` "
                        "does not work for it", f"its record is the folder {room}"]
            if pkg.caskroom_data:
                evidence.append(f"that folder also holds data: {some(pkg.caskroom_data)}")
            remedies = _drop_cask_record(ctx, room)
            out.append(_issue("brew-orphan-caskroom", token, b, evidence, remedies, confirm_each=_runs(remedies),
                              title=f"The cask {token} is installed, but Homebrew's package list does not have it "
                                    "under any name"))
    return out


# Strays, PATH, renames, inventory, root ownership and brew.env -------------------------

def _strays_in_usr_local(ctx: _Scan) -> list[Issue]:
    """Report the five `brew doctor check_for_stray_*` checks, which carry Homebrew's allow-lists, on arm64

    There `/usr/local` is no native Homebrew prefix; the files are the host's, so a finding names no instance and
    one that two instances report is kept once.

    @param ctx  the scan
    @returns    the findings, with a not-checked one wherever `brew doctor` gave no usable report
    """
    code = "brew-strays-in-usr-local"
    if ctx.host_arch != "arm64" or not ctx.brews:
        return []
    what = "whether /usr/local holds libraries or header files that Homebrew did not install"
    out: list[Issue] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    ran = [(b, b.doctor) for b in ctx.brews if b.doctor is not None]
    if not ran:
        out.append(_skipped(code, None, what, "no Homebrew on this Mac can run `brew doctor`, which finds them"))
    for b, report in ran:
        if report.failure:
            out.append(_skipped(code, b, what, report.failure))
            continue
        for check, (directory, what_files) in STRAY.items():
            block = report.warnings.get(check)
            if not block or (check, tuple(block)) in seen:
                continue
            seen.add((check, tuple(block)))
            files = [line.strip() for line in block[1:] if line.startswith("  ") and line.strip()]
            note = _note(code, directory, "Fix: delete or move them, unless you put them there on purpose.", check)
            evidence = [some(f[len(directory) + 1:] if f.startswith(directory + "/") else f for f in files),
                        "software that Homebrew or MacPorts builds can pick them up by mistake"]
            evidence += _each(files)
            out.append(_issue(code, directory, None, evidence, [note],
                              title=f"{directory} holds {what_files} that Homebrew did not install"))
    return out


def _path_order(ctx: _Scan) -> list[Issue]:
    """Report `/usr/bin` before `<prefix>/bin` in the live PATH

    The fix named here is the one by hand, which holds for every installation; `doctor` names `env-cleanup` in
    its place for the installation that command keeps.

    @param ctx  the scan
    @returns    the findings
    """
    environment = ctx.bundle.result.environment
    entries = [env_shell.PathEntry(text=e.get("text") or "", path=e.get("path"),
                                   instance_prefix=e.get("instance_prefix"), exists=e.get("exists"),
                                   usr_local=bool(e.get("usr_local")))
               for e in (environment.get("live") or {}).get("PATH") or [] if isinstance(e, dict)]
    usr_bin = env_shell.path_index(entries, "/usr/bin")
    if usr_bin is None:
        return []
    out: list[Issue] = []
    for b in ctx.brews:
        bin_dir = os.path.join(b.prefix, "bin")
        own = env_shell.path_index(entries, bin_dir)
        if own is None or own < usr_bin:
            continue
        note = _note("brew-path-order", bin_dir, f"Fix, if this is the Homebrew you keep: put {bin_dir} in front of "
                     "/usr/bin in your shell's login file.", "path")
        evidence = [f"/usr/bin is entry {usr_bin + 1} of your PATH, and {bin_dir} is entry {own + 1}"]
        out.append(_issue("brew-path-order", bin_dir, b, evidence, [note],
                          title=f"/usr/bin comes before {bin_dir} on your PATH, so a command of macOS wins over "
                                "Homebrew's command of the same name"))
    return out


def _renamed_keg(ctx: _Scan) -> list[Issue]:
    """Report a Cellar rack under a formula's old name, a key of `formula_renames`, with `brew migrate <old>`

    @param ctx  the scan
    @returns    the findings
    """
    code = "brew-renamed-keg"
    out: list[Issue] = []
    for b in ctx.brews:
        if b.cat is None:
            continue
        for pkg in b.packages("formula"):
            if not b.inv.kegs.get(pkg.name):
                continue
            for rack in b.racks(pkg):
                old = os.path.basename(rack)
                new = b.cat.renamed_to(old)
                if not new or new == old:
                    continue
                title = f"Homebrew renamed {old} to {new}, and the installed copy still has the old name"
                evidence = [f"its folder is {rack}"]
                if not b.inst.drivable:
                    out.append(_issue(code, old, b, evidence, [b.no_fix(code, rack)], title=title))
                    continue
                migrate = actions.migrate(b.inst, ctx.host_arch, action_id(code, rack, "migrate"), old)
                out.append(_issue(code, old, b, evidence, [migrate], title=title, auto_fix=True,
                                  repairs_install=True))
    return out


def _error_lines(text: str) -> list[str]:
    """Return a failed probe's text as evidence lines: its first line, Homebrew's `Error:` lines, then the rest

    The default report shows the first lines of a finding, and Homebrew states the cause on its `Error:` lines.

    @param text  the error text of the inventory probes
    @returns     the lines, each once
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    first = lines[:1] + [line for line in lines[1:] if line.startswith("Error:")]
    return limited(list(dict.fromkeys(first + lines)))


def _degraded_inventory(ctx: _Scan) -> list[Issue]:
    """Report the `inventory_error` of a Homebrew instance; the tool runs no remedy

    A failed `brew info` leaves the disk walk alone, and its finding blocks `CASKS` and `REMOVE` too,
    because cask dependencies and artifacts are unknown. After a good `brew info`, a failed `brew outdated`
    or `brew deps` gets an INFO finding, and a failed `brew missing` the not-checked one of its check.

    @param ctx  the scan
    @returns    the findings
    """
    out: list[Issue] = []
    for b in ctx.brews:
        error = b.inst.inventory_error
        if not error:
            continue
        if not b.inv.used_json:
            code = "brew-degraded-inventory"
            remedies = [actions.manual(b.inst, action_id(code, b.prefix, "manual"),
                                       ["info", "--json=v2", "--installed"],
                                       "Fix: run it yourself and resolve what Homebrew reports", ctx.host_arch),
                        _note(code, b.prefix, "Then run `brew-ports doctor --rescan`.")]
            out.append(_issue(code, b.prefix, b, _error_lines(error), remedies,
                              title="`brew info` failed, so brew-ports knows only part of what this Homebrew has "
                                    "installed"))
            continue
        lost = {probe: text for probe, text in (
            ("brew outdated", "packages with a newer version are listed without the number of that version"),
            ("brew deps", "dependencies come from Homebrew's install records alone")) if probe in error}
        if lost:
            code = "brew-failed-probe"
            note = _note(code, b.prefix, "Nothing to do: brew-ports works with what `brew info` gave it.")
            out.append(_issue(code, b.prefix, b, list(lost.values()) + _error_lines(error), [note],
                              title=f"{series(f'`{probe}`' for probe in lost)} failed, so brew-ports knows less "
                                    "about this Homebrew"))
    return out


def _root_owned_keg(ctx: _Scan) -> list[Issue]:
    """Report root-owned paths under a keg or its `opt` link, left by `sudo brew services start`

    The remedies are only printed: the tool never walks a user-owned tree as root.

    @param ctx  the scan
    @returns    the findings
    """
    code = "brew-root-owned-keg"
    out: list[Issue] = []
    for b in ctx.brews:
        for name, paths in sorted(b.inv.root_owned.items()):
            rack = os.path.join(b.prefix, "Cellar", name)
            binary = b.inst.binary or os.path.join(b.prefix, "bin", "brew")
            # The files lie in the formula's versions or are its `opt` link; -h hands over a link, not its target.
            tops = [rack] + sorted({p for p in paths if p != rack and not p.startswith(rack + os.sep)
                                    and os.path.dirname(p) == os.path.join(b.prefix, "opt")})
            remedies = [_note(code, rack, f"Fix: sudo {binary} services stop {name}", "stop"),
                        _note(code, rack, "Then give the files back to yourself: sudo chown -R -h \"$(whoami)\" "
                              f"{' '.join(shlex.quote(top) for top in tops)}")]
            evidence = [some(paths), f"a move out of this Homebrew leaves {name} installed while they do"]
            evidence += _each(paths)
            out.append(_issue(code, name, b, evidence, remedies,
                              title=f"Files of {name} belong to root, so `brew` cannot change them"))
    return out


def _env_line_effect(name: str, value: str) -> str | None:
    """Say how a `brew.env` assignment undoes the `brew` profile, or None when the profile's effect stands

    A set-list variable counts when empty or one of Homebrew's falsy words, a deny-listed one with any value but an
    empty one.

    @param name   the variable
    @param value  its value in the file
    @returns      the effect, or None
    """
    if name in BREW_SET:
        if not value or value.lower() in FALSY:
            return f"turns off {name}={BREW_SET[name]}, which brew-ports sets for every `brew` command it runs"
        return None
    if value and (name in BREW_DENY or name.startswith(BREW_DENY_PREFIXES)):
        return f"sets {name}, which brew-ports keeps away from every `brew` command it runs"
    return None


def _env_override(ctx: _Scan) -> list[Issue]:
    """Report, per drivable instance and file, the deciding `brew.env` lines that change the `brew` profile

    The last line `bin/brew` exports decides; while this finding holds, `doctor --fix` runs none of the instance's
    `brew` remedies.

    @param ctx  the scan
    @returns    the findings
    """
    out: list[Issue] = []
    for b in ctx.brews:
        if not b.inst.drivable:
            continue
        deciding: dict[str, locate.EnvLine] = {}
        for line in b.inv.brew_env:
            deciding[line.name] = line
        by_file: dict[str, list[locate.EnvLine]] = {}
        for line in deciding.values():
            if _env_line_effect(line.name, line.value):
                by_file.setdefault(line.path, []).append(line)
        for path, lines in sorted(by_file.items()):
            shown = tilde(path, ctx.home)
            evidence = [f"line {line.lineno}: {line.name}={line.value} {_env_line_effect(line.name, line.value)}"
                        for line in sorted(lines, key=lambda line: line.lineno)]
            note = _note("brew-env-override", path, f"Fix: remove these lines from {shown}, or put a # in front of "
                         "each.")
            out.append(_issue("brew-env-override", path, b, evidence, [note],
                              title=f"{shown} changes settings that brew-ports relies on when it runs `brew`"))
    return out


DETECTORS = (_several_prefixes, _unusable_or_dirty, _stale_catalogue, _keg_without_receipt, _deleted_formula,
             _deprecated_formula, _unlinked_keg, _broken_symlink, _several_versions, _missing_dependency,
             _broken_linkage, _outdated_keg, _pinned_formula, _dirty_tap, _unwritable_prefix, _orphan_service,
             _missing_app, _orphan_caskroom, _strays_in_usr_local, _path_order, _renamed_keg, _degraded_inventory,
             _root_owned_keg, _env_override)


# Public interface -------------------------------------------------------------------

def detect(bundle: "ScanBundle", runner) -> list[Issue]:
    """Run every Homebrew detector over the bundle's instances, in table order

    @param bundle  the scan bundle
    @param runner  the runner the probes go through
    @returns       the findings
    """
    ctx = _context(bundle, runner)
    issues: list[Issue] = []
    for detector in DETECTORS:
        issues.extend(detector(ctx))
    return issues


def needs_terminal_answer(issue: Issue) -> bool:
    """Return whether the remedy removes a package, keg or Caskroom record, which needs a per-item answer on a terminal

    The answer keeps `--yes` from turning removals into a sweep.

    @param issue  a Homebrew finding
    @returns      True for a removal
    """
    if issue.code in ("brew-deleted-formula", "brew-several-versions", "brew-orphan-caskroom"):
        return True
    return issue.code == "brew-keg-without-receipt" and "uninstall" in _steps(issue)


_PACKAGE_STEPS = {
    "brew-keg-without-receipt": ("formula", ("reinstall", "uninstall")),
    "brew-deleted-formula": ("formula", ("uninstall",)),
    "brew-broken-linkage": ("formula", ("reinstall",)),
    "brew-missing-app": ("cask", ("reinstall",)),
    "brew-orphan-caskroom": ("cask", ("rm",)),
}


def removes_package(issue: Issue) -> tuple[str, str] | None:
    """Return `(kind, name)` when a remedy that runs removes or replaces a package, else None

    `doctor --fix` then writes the phase 1 snapshot first and follows the phase 5 service rules.

    @param issue  a Homebrew finding
    @returns      the package's kind and name, or None
    """
    rule = _PACKAGE_STEPS.get(issue.code)
    if rule is None or not issue.subject or not _steps(issue).intersection(rule[1]):
        return None
    return rule[0], issue.subject


def current_keg(prefix: str, name: str) -> str | None:
    """Return the keg `<prefix>/opt/<name>` names, else the newest keg of its rack

    @param prefix  the Homebrew prefix
    @param name    the formula
    @returns       the keg directory, or None when the rack holds none
    """
    opt = os.path.join(prefix, "opt", name)
    if os.path.islink(opt) and os.path.isdir(opt):
        return os.path.realpath(opt)
    rack = os.path.join(prefix, "Cellar", name)
    try:
        versions = [v for v in os.listdir(rack) if not v.startswith(".")
                    and os.path.isdir(os.path.join(rack, v)) and not os.path.islink(os.path.join(rack, v))]
    except OSError:
        return None
    return os.path.join(rack, max(versions, key=version_key)) if versions else None


def verify(issue: Issue, runner, bundle: "ScanBundle") -> bool | None:
    """Return whether a reinstall worked, read from the host

    The keg has its receipt, marked installed on request when the tab step ran, or no `missing` reference for
    broken linkage; None for every other finding.

    @param issue   the finding whose remedies ran
    @param runner  the runner the linkage probe goes through
    @param bundle  the scan bundle, for the instances
    @returns       True when it worked, False when not, None when the finding has no such check
    """
    steps = _steps(issue)
    if (issue.code not in ("brew-keg-without-receipt", "brew-broken-linkage") or "reinstall" not in steps
            or not issue.instance_prefix or not issue.subject):
        return None
    keg = current_keg(issue.instance_prefix, issue.subject)
    if keg is None:
        return False
    if issue.code == "brew-keg-without-receipt":
        receipt = inventory.read_json(os.path.join(keg, inventory.RECEIPT))
        return receipt is not None and ("tab" not in steps or receipt.get("installed_on_request") is True)
    key = f"{issue.instance_prefix}|formula|{issue.subject}"
    report = env_linkage.scan(runner, {key: env_linkage.keg_binaries(keg)}, bundle.result.instances)
    return not env_linkage.references(report, ["missing"])

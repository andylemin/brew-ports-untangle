"""What `doctor` says: what it checked, what stops a move, the findings by what they mean, and what to run next"""

from __future__ import annotations

import os
import shlex
from collections.abc import Sequence

from .model import Action, Blocks, Instance, Issue, Severity
from .report import FIX_OFFER, NOT_CHECKED, SCAN_REUSED, at, counted, has, place, series, some, typed

EVIDENCE_SHOWN = 3                  # evidence lines of one finding in the default report
FIX = "brew-ports doctor --fix"     # makes the fixes; on a Mac with several installations, `keeps` adds which stays
OFFER = "Fix: " + FIX               # starts the line of a fix that it makes, on a Mac with one installation
STOPS = "To fix before a move"
BROKEN = "Broken or at risk"
CLEANUP = "Worth cleaning up"
INFORMATION = "For information"
UPKEEP = "Only if you keep %s"
UNCHECKED = "Checks that could not run"
SCAN_NOTES = "Notes from the scan"
NOTHING_TO_DO = "Nothing to do"     # starts the line of a finding that asks nothing of the reader
BREW_ENV_FIRST = "No fix until the brew.env lines that `brew-ports doctor` lists are removed."
EXIT_1 = "Exit status 1: something needs a fix before a move, or is broken."
QUESTION = "Make this fix?"
QUESTIONS = "Make these %d fixes?"
NOTHING_TO_FIX = ("No finding has a fix that `doctor --fix` can make. `brew-ports doctor` lists what was found and "
                  "what to do about it.")
ONLY_KEPT = "doctor --fix repairs only the installation you keep"
NOT_KEPT = f"No fix offered: {ONLY_KEPT}."      # the fix line of a finding about another installation
TWICE_UNKNOWN = "Which packages are installed twice: this Mac has no package list for %s"
TWICE_UNREAD = "Which packages of %s are installed twice: what is installed there could not be read"
DRY_RUN = "Dry run: nothing changes."
DRY_RUN_END = "Dry run: nothing changed."
STOPPED = {Blocks.TARGET: "a move into %s", Blocks.UNINSTALL: "a move out of %s",
           Blocks.CASKS: "uninstalling the apps of %s", Blocks.REMOVE: "uninstalling %s itself"}
# One line for several findings of one kind in one installation: what they share, said of one subject and of several.
SEVERAL = {
    "brew-deprecated-formula": ("1 installed formula is deprecated or disabled",
                                "{count} installed formulae are deprecated or disabled"),
    "brew-outdated-keg": ("1 package has a newer version", "{count} packages have a newer version"),
    "brew-broken-symlink": ("1 link points at a file that is gone", "{count} links point at files that are gone"),
    "brew-several-versions": ("1 formula has more than one version installed",
                              "{count} formulae have more than one version installed"),
    "brew-pinned-formula": ("1 formula is pinned, so Homebrew does not upgrade it",
                            "{count} formulae are pinned, so Homebrew does not upgrade them"),
    "ports-inactive-versions": ("1 port has versions that are stored but not in use",
                                "{count} ports have versions that are stored but not in use"),
    "ports-unrequested-leaf": ("1 port is a leftover dependency that nothing needs",
                               "{count} ports are leftover dependencies that nothing needs"),
    "ports-obsolete-port": ("1 installed port is missing from MacPorts' package list",
                            "{count} installed ports are missing from MacPorts' package list"),
    "ports-replaced-port": ("1 port was replaced by another in MacPorts",
                            "{count} ports were replaced by others in MacPorts"),
    "ports-unregistered-file": ("1 file was not installed by any port",
                                "{count} files were not installed by any port"),
}


def known(instances: Sequence[Instance]) -> dict[str, Instance]:
    """Return installations by prefix

    @param instances  the installations the scan found
    @returns          the lookup the report's functions take
    """
    return {inst.prefix: inst for inst in instances}


def checked(instances: Sequence[Instance]) -> str:
    """Return the report's first line: what the checks looked at

    @param instances  the installations the scan found
    @returns          the line
    """
    if not instances:
        return "Checked your shell files and your PATH. Neither Homebrew nor MacPorts is installed on this Mac."
    return f"Checked {', '.join(place(inst) for inst in instances)}, your shell files and your PATH."


def keeping(target: Instance) -> str:
    """Return the line that names the installation that the user keeps

    @param target  that installation
    @returns       the line
    """
    return f"The installation you keep: {at(target)}."


def keeps(inst: Instance, instances: dict[str, Instance]) -> str:
    """Return the options that name an installation as the one the user keeps, as `doctor` and `plan` take them

    @param inst       the installation
    @param instances  the installations by prefix
    @returns          such as ` --target brew`, with ` --target-prefix` too where the Mac has several installations
                      of that manager; nothing on a Mac with one installation, where there is nothing to choose
    """
    if len(instances) < 2:
        return ""
    alone = sum(1 for other in instances.values() if other.manager is inst.manager) == 1
    return f" --target {inst.manager.value}" + ("" if alone else f" --target-prefix {shlex.quote(inst.prefix)}")


def fix_command(issue: Issue, instances: dict[str, Instance], target: Instance | None = None) -> str:
    """Return the command that offers a finding's fix: `doctor --fix` for the installation the finding is about

    A fix of a finding about no installation is offered whichever installation stays, so the chosen one names
    it, or else any of them.

    @param issue      a finding
    @param instances  the installations by prefix
    @param target     the installation that `--target` says the user keeps, or None
    @returns          such as `brew-ports doctor --fix --target brew`
    """
    inst = instances.get(issue.instance_prefix or "") or target or next(iter(instances.values()), None)
    return FIX + (keeps(inst, instances) if inst is not None else "")


def fix_offer(issue: Issue, instances: dict[str, Instance], target: Instance | None = None) -> str | None:
    """Return how the line of a fix that `doctor --fix` makes starts: `Fix:`, then the command that offers it

    On a Mac with several installations the command repairs the finding's installation alone. While the user
    has not said which one stays, the line names that condition.

    @param issue      a finding
    @param instances  the installations by prefix
    @param target     the installation that `--target` says the user keeps, or None
    @returns          such as `Fix: brew-ports doctor --fix`, or `Fix, if you keep MacPorts at /opt/local:
                      brew-ports doctor --fix --target ports`; None for a finding about an installation other
                      than the target, which `doctor --fix` does not repair
    """
    if not in_kept(issue, target, instances):
        return None
    inst = instances.get(issue.instance_prefix or "")
    condition = f", if you keep {at(inst)}" if inst is not None and target is None and len(instances) > 1 else ""
    return f"Fix{condition}: {fix_command(issue, instances, target)}"


def needs_target(instances: dict[str, Instance]) -> str:
    """Return why `doctor --fix` stops on a Mac with several installations when no `--target` names the one to keep

    @param instances  the installations by prefix
    @returns          the error, with the options that name each installation
    """
    options = [f"{keeps(inst, instances).strip()} for {at(inst)}" for inst in instances.values()]
    both = len({inst.manager for inst in instances.values()}) > 1
    return (f"{ONLY_KEPT}, so it needs to know which one that is: add {', '.join(options[:-1])} or {options[-1]}."
            + (" `brew-ports recommend` compares a move in each direction." if both else ""))


def no_target(manager: str, prefix: str | None, found: Sequence[Instance]) -> str:
    """Return why `--target` names no installation to keep

    @param manager  `Homebrew` or `MacPorts`, the manager that `--target` names
    @param prefix   the `--target-prefix` value, or None
    @param found    the installations of that manager on this Mac
    @returns        the error
    """
    if prefix:
        return f"there is no {manager} at {prefix}" + has(found, manager)
    if not found:
        return (f"{manager} is not installed, so there is none to keep. `brew-ports doctor` without --target "
                "checks what this Mac has.")
    return f"this Mac has {' and '.join(at(inst) for inst in found)}: say which one you keep with --target-prefix"


def elsewhere(fixes: Sequence[Issue], stopping: Sequence[Issue], instances: dict[str, Instance],
              chosen: str = "") -> list[str]:
    """Return the lines about the installations other than the one that stays, in which `doctor --fix` repairs nothing

    @param fixes      the findings about such an installation that `doctor --fix` could repair
    @param stopping   the findings about such an installation that stop the move or a part of it
    @param instances  the installations by prefix
    @param chosen     the options that name the installation that stays, as `keeps` gives them
    @returns          how many fixes are left out, and each finding that stops the move with what it stops;
                      nothing without such a finding
    """
    lines: list[str] = []
    counts: dict[str, int] = {}
    for issue in fixes:
        inst = instances.get(issue.instance_prefix or "")
        where = at(inst) if inst is not None else str(issue.instance_prefix)
        counts[where] = counts.get(where, 0) + 1
    if counts:
        left_out = series(f"{counted(count, 'fix', 'fixes')} in {where}" for where, count in counts.items())
        lines += ["", f"Not offered: {left_out}. {ONLY_KEPT}."]
    if stopping:
        one = len(stopping) == 1
        lines += ["", f"{counted(len(stopping), 'thing')} outside the installation you keep "
                  f"{'stops' if one else 'stop'} the move or a part of it:"]
        for issue in stopping:
            lines += [f"  {named(issue, instances)}", f"      {stopped(issue, instances)}"]
        lines.append(f"  `brew-ports doctor{chosen}` lists what to do about {'it' if one else 'each'}.")
    return lines


def stops(issue: Issue) -> bool:
    """Return whether a finding needs a fix before a move, or before a part of one

    @param issue  a finding
    @returns      True for a CRITICAL finding and for one that blocks a kind of plan
    """
    return issue.severity is Severity.CRITICAL or bool(issue.blocks)


def what_stops(issue: Issue, instances: dict[str, Instance]) -> str:
    """Return what a finding stops, as the words that follow `stops`

    @param issue      a finding that `stops`
    @param instances  the installations by prefix
    @returns          such as `every move` or `a move out of MacPorts at /opt/local`
    """
    if issue.severity is Severity.CRITICAL or Blocks.ANY in issue.blocks:
        return "every move"
    inst = instances.get(issue.instance_prefix or "")
    where = at(inst) if inst is not None else issue.instance_prefix or "that installation"
    return series(text % where for block, text in STOPPED.items() if block in issue.blocks)


def stopped(issue: Issue, instances: dict[str, Instance]) -> str:
    """Return what a finding stops, as a sentence

    @param issue      a finding that `stops`
    @param instances  the installations by prefix
    @returns          such as `This stops a move out of MacPorts at /opt/local.`
    """
    return f"This stops {what_stops(issue, instances)}."


def asks_nothing(issue: Issue) -> bool:
    """Return whether a finding leaves the reader nothing to do

    @param issue  a finding
    @returns      True when each of its fix lines starts with `NOTHING_TO_DO`
    """
    lines = fix_lines(issue)
    return bool(lines) and all(line.startswith(NOTHING_TO_DO) for line in lines)


def heading(issue: Issue, instances: dict[str, Instance]) -> str:
    """Return the group a finding is printed under

    On a Mac with several installations, a finding of one installation's own upkeep that stops nothing matters
    only to someone who keeps that installation, so it goes under that installation's heading. A finding that
    is not broken and leaves nothing to do is information, whatever its severity.

    @param issue      a finding
    @param instances  the installations by prefix
    @returns          the group's heading
    """
    if stops(issue):
        return STOPS
    if issue.severity is Severity.HIGH:
        return BROKEN
    inst = instances.get(issue.instance_prefix or "")
    if inst is not None and len(instances) > 1 and issue.code.split("-", 1)[0] in ("brew", "ports"):
        return UPKEEP % at(inst)
    return INFORMATION if issue.severity is Severity.INFO or asks_nothing(issue) else CLEANUP


def _command(action: Action) -> str:
    """Return a remedy's command as the user would type it

    @param action  a command remedy
    @returns       the shell-quoted command, `sudo` included; one for the user to run keeps `arch -x86_64`, which
                   the `brew` of an Intel Homebrew on an Apple Silicon Mac needs
    """
    return typed(action.argv, action.sudo, intel=action.manual)


def runs(issue: Issue) -> list[Action]:
    """Return the commands of a finding's fix that brew-ports runs itself

    @param issue  a finding
    @returns      its command remedies that are not for the user to run, in order
    """
    return [a for a in issue.remedies if a.kind == "command" and not a.manual]


def _offered(issue: Issue) -> bool:
    """Return whether `doctor --fix` offers to fix a finding

    @param issue  a finding
    @returns      True when it has a command that `--fix` runs after a question
    """
    return (issue.auto_fix or issue.confirm_each) and bool(runs(issue))


def _worded(issue: Issue) -> str | None:
    """Return what `doctor --fix` does for a finding, where the finding says it in words of its own

    @param issue  a finding
    @returns      what follows `FIX_OFFER` in the one of its notes that starts with it; None without such a note
    """
    for action in issue.remedies:
        if action.kind == "note" and action.description.startswith(FIX_OFFER):
            return action.description[len(FIX_OFFER):].removesuffix(")")
    return None


def does(issue: Issue) -> str:
    """Return what `doctor --fix` does for a finding once the user agrees

    @param issue  a finding that `doctor --fix` offers to fix
    @returns      the finding's own words for it, else its commands: "runs `brew link jq`"
    """
    commands = ", then ".join(f"`{_command(a)}`" for a in runs(issue))
    return _worded(issue) or (f"runs {commands}" if commands else "makes the repair")


def fix_lines(issue: Issue, blocked: bool = False, lead: str | None = OFFER) -> list[str]:
    """Return what to do about a finding: the fix `doctor --fix` makes, the commands for the user, the notes

    @param issue    a finding
    @param blocked  whether a `brew.env` file keeps `doctor --fix` from the finding's fix
    @param lead     how the line of that fix starts, as `fix_offer` gives it; None when `doctor --fix` leaves the
                    finding's installation alone
    @returns        the lines, in the order of the remedies; a note is printed as its site worded it
    """
    def made() -> str:
        if lead is None:
            return NOT_KEPT
        return BREW_ENV_FIRST if blocked else f"{lead} (asks, then {does(issue)})"

    lines: list[str] = []
    offered = issue.auto_fix or issue.confirm_each
    worded = _worded(issue) is not None
    for action in issue.remedies:
        if action.kind == "note" and action.description.startswith(FIX_OFFER):
            lines.append(made())
        elif action.kind == "note":
            lines.append(action.description)
        elif action.manual:
            lines.append(f"{action.description}: {_command(action)}" if action.description
                         else f"Fix: {_command(action)}")
        elif not offered:
            lines.append(f"Fix: {_command(action)}")
        elif not worded and action is runs(issue)[0]:
            lines.append(made())
    return lines


def unchecked(issue: Issue) -> bool:
    """Return whether a finding stands for a check that could not run

    @param issue  a finding
    @returns      True when the report lists it with the checks that could not run, not with what was found
    """
    return issue.title.startswith(NOT_CHECKED)


def _where(issue: Issue, instances: dict[str, Instance]) -> str:
    """Return the installation of a finding, for a title that does not name it

    @param issue      a finding
    @param instances  the installations by prefix
    @returns          such as ` (Homebrew at /opt/homebrew)`; nothing on a Mac with one installation
    """
    inst = instances.get(issue.instance_prefix or "")
    return f" ({at(inst)})" if inst is not None and len(instances) > 1 and inst.prefix not in issue.title else ""


def _evidence(issue: Issue, verbose: bool) -> list[str]:
    """Return a finding's evidence lines as the report shows them

    @param issue    a finding
    @param verbose  whether to show every line
    @returns        the first lines, and how many more there are
    """
    shown = issue.evidence if verbose else issue.evidence[:EVIDENCE_SHOWN]
    lines = [f"      {line}" for line in shown]
    if len(issue.evidence) > len(shown):
        lines.append(f"      and {counted(len(issue.evidence) - len(shown), 'more line')} (--verbose shows them)")
    return lines


def finding(issue: Issue, instances: dict[str, Instance], verbose: bool = False, blocked: bool = False,
            target: Instance | None = None) -> list[str]:
    """Return the lines of one finding: its title, what was found, what it stops, what to do

    The title is a sentence that names the finding's subject. Outside the group of its own installation, a
    finding whose title does not name that installation gets it appended.

    @param issue      a finding
    @param instances  the installations by prefix
    @param verbose    whether to print the finding's name and every evidence line
    @param blocked    whether a `brew.env` file keeps `doctor --fix` from the finding's fix
    @param target     the installation that `--target` says the user keeps, or None
    @returns          the lines, indented for the report
    """
    inst = instances.get(issue.instance_prefix or "")
    own = inst is not None and heading(issue, instances) == UPKEEP % at(inst)
    lines = [f"  {issue.title}{'' if own else _where(issue, instances)}" + (f"   [{issue.code}]" if verbose else "")]
    lines += _evidence(issue, verbose)
    if stops(issue):
        lines.append(f"      {stopped(issue, instances)}")
    return lines + [f"      {line}" for line in fix_lines(issue, blocked, fix_offer(issue, instances, target))]


def _name(issue: Issue) -> str:
    """Return what the line for several findings of one kind calls one of them

    @param issue  a finding
    @returns      its subject: a path inside its installation without the installation's folder, and an old
                  version by the name of its formula
    """
    subject, prefix = issue.subject or "", issue.instance_prefix or ""
    if issue.code == "brew-several-versions" and os.path.isabs(subject):
        return os.path.basename(os.path.dirname(subject))
    if prefix and subject.startswith(prefix.rstrip("/") + "/"):
        return subject[len(prefix.rstrip("/")) + 1:]
    return subject


def several(issues: Sequence[Issue], blocked: bool = False, lead: str | None = OFFER) -> list[str]:
    """Return the lines of several findings of one kind in one installation

    @param issues   the findings, which share a name that `SEVERAL` words
    @param blocked  whether a `brew.env` file keeps `doctor --fix` from their fixes
    @param lead     how the line of their fixes starts, as `fix_offer` gives it; None when `doctor --fix` leaves
                    their installation alone
    @returns        what they share and what each is about, then what to do about them
    """
    first = issues[0]
    names = list(dict.fromkeys(_name(i) for i in issues))
    one, many = SEVERAL[first.code]
    lines = [f"  {one if len(names) == 1 else many.format(count=len(names))}: {some(names)}"]
    each = [fix_lines(issue, blocked, lead) for issue in issues]
    # The line of each one's own fix gives way to one line for them all.
    shared = [line for line in each[0] if all(line in other for other in each[1:])
              and not (lead and line.startswith(f"{lead} (asks, then "))]
    if lead and _offered(first) and not blocked:
        worded = _worded(first) if all(_worded(i) == _worded(first) for i in issues) else None
        shared.insert(0, f"{lead} (asks about each{', then ' + worded if worded else ''})")
    return lines + [f"      {line}" for line in shared or ["`brew-ports doctor --verbose` lists each with what to do."]]


def groups(issues: Sequence[Issue], instances: dict[str, Instance]) -> list[tuple[str, list[Issue]]]:
    """Return the findings by group, in the order the report prints the groups

    @param issues     the findings, sorted
    @param instances  the installations by prefix
    @returns          each heading with its findings: what stops a move first, the information last; a finding
                      that stands for a check that could not run is in no group
    """
    order = [STOPS, BROKEN, CLEANUP] + [UPKEEP % at(inst) for inst in instances.values()] + [INFORMATION]
    found: dict[str, list[Issue]] = {}
    for issue in issues:
        if not unchecked(issue):
            found.setdefault(heading(issue, instances), []).append(issue)
    return [(name, found[name]) for name in order if name in found]


def not_run(issues: Sequence[Issue], instances: dict[str, Instance], notes: Sequence[str],
            verbose: bool = False) -> list[str]:
    """Return the report's last section: the checks that could not run, and why

    @param issues     the findings, of which those that stand for a check that could not run are listed
    @param instances  the installations by prefix
    @param notes      the checks that the detectors could not run
    @param verbose    whether to print every evidence line
    @returns          the section with its heading; nothing when every check ran
    """
    lines: list[str] = []
    for issue in issues:
        if unchecked(issue):
            what = issue.title[len(NOT_CHECKED):]
            lines.append(f"  {what[:1].upper()}{what[1:]}{_where(issue, instances)}")
            lines += _evidence(issue, verbose)
    lines += [f"  {text}" for text in notes]
    return ["", UNCHECKED] + lines if lines else []


def stops_what(issues: Sequence[Issue], instances: dict[str, Instance]) -> str:
    """Return the answer to "can I move?"

    @param issues     the findings
    @param instances  the installations by prefix
    @returns          what the findings that stop a move stop when they all stop the same; else that each says it
    """
    found = [issue for issue in issues if stops(issue) and not unchecked(issue)]
    if not found:
        return "Nothing stops a move."
    what = list(dict.fromkeys(what_stops(issue, instances) for issue in found))
    if len(what) == 1:
        return f"{counted(len(found), 'thing')} {'stops' if len(found) == 1 else 'stop'} {what[0]}, listed first."
    return f"{counted(len(found), 'thing')} stop a move or a part of one, listed first with what each stops."


def verdict(issues: Sequence[Issue], instances: dict[str, Instance]) -> str:
    """Return the answer to "can I move?", then how much else was found

    @param issues     the findings
    @param instances  the installations by prefix
    @returns          the sentence that follows the opening line
    """
    if all(unchecked(issue) for issue in issues):
        return "No problems found."
    count = {name: len(found) for name, found in groups(issues, instances)}
    first = stops_what(issues, instances)
    rest = []
    if BROKEN in count:
        rest.append(f"{counted(count[BROKEN], 'thing')} {'is' if count[BROKEN] == 1 else 'are'} broken or at risk")
    if CLEANUP in count:
        rest.append(f"{counted(count[CLEANUP], 'thing')} {'is' if count[CLEANUP] == 1 else 'are'} worth cleaning up")
    upkeep = sum(n for name, n in count.items() if name not in (STOPS, BROKEN, CLEANUP, INFORMATION))
    if upkeep:
        rest.append(f"{counted(upkeep, 'thing')} {'matters' if upkeep == 1 else 'matter'} only if you keep the "
                    f"installation {'it is' if upkeep == 1 else 'they are'} in")
    return first + (f" {series(rest)[:1].upper()}{series(rest)[1:]}." if rest else "")


def render(issues: Sequence[Issue], instances: Sequence[Instance], notes: Sequence[str] = (), *,
           reused: bool = False, verbose: bool = False, scan_notes: Sequence[str] = (),
           target: Instance | None = None) -> list[str]:
    """Return the text report of `doctor`

    @param issues      the findings, sorted
    @param instances   the installations the scan found
    @param notes       the checks that the detectors could not run
    @param reused      whether the findings come from a recent scan
    @param verbose     whether to print every finding on its own, with its name and all its evidence
    @param scan_notes  what the scan noted, which only a verbose report prints
    @param target      the installation that `--target` says the user keeps, or None
    @returns           the report lines
    """
    by_prefix = known(instances)
    lines = [checked(instances)] + ([keeping(target)] if target is not None else [])
    lines += ([SCAN_REUSED] if reused else []) + ["", verdict(issues, by_prefix)]
    for name, found in groups(issues, by_prefix):
        lines += ["", f"{name} ({len(found)})"]
        # Findings of one kind in one installation that `doctor --fix` offers print as one, the rest as another.
        kinds: dict[tuple[str, str | None, bool, bool], list[Issue]] = {}
        for issue in found:
            key = (issue.code, issue.instance_prefix, _offered(issue), refused(issue, issues))
            kinds.setdefault(key, []).append(issue)
        for (code, _, _, blocked), same in kinds.items():
            if len(same) > 1 and code in SEVERAL and not verbose:
                lines += several(same, blocked, fix_offer(same[0], by_prefix, target))
            else:
                for issue in same:
                    lines += finding(issue, by_prefix, verbose, blocked, target)
    lines += not_run(issues, by_prefix, notes, verbose)
    if verbose and scan_notes:
        lines += ["", SCAN_NOTES] + [f"  {text}" for text in scan_notes]
    return lines


def refused(issue: Issue, issues: Sequence[Issue]) -> bool:
    """Return whether a `brew.env` file that changes brew-ports' settings keeps `doctor --fix` from a finding's fix

    @param issue   a finding
    @param issues  every finding, of which `brew-env-override` names the installations whose `brew` is not run
    @returns       True when one of the finding's commands runs the `brew` of such an installation
    """
    overrides = {i.instance_prefix for i in issues if i.code == "brew-env-override"}
    uses_brew = any(a.env_profile == "brew" for a in runs(issue))
    return bool(overrides) and uses_brew and (issue.instance_prefix in overrides or None in overrides)


def in_kept(issue: Issue, kept: Instance | None, instances: dict[str, Instance]) -> bool:
    """Return whether a finding is about the installation the user keeps, or about no installation

    @param issue      a finding
    @param kept       the installation that stays; None when every installation counts as kept
    @param instances  the installations by prefix
    @returns          True when `doctor --fix` may repair what the finding is about
    """
    prefix = issue.instance_prefix
    return kept is None or prefix == kept.prefix or prefix not in instances


def fixable(issues: Sequence[Issue], kept: Instance | None = None,
            instances: dict[str, Instance] | None = None) -> int:
    """Return how many findings `doctor --fix` offers to fix

    @param issues     the findings
    @param kept       the installation that stays; None counts the fixes of every installation
    @param instances  the installations by prefix, which `kept` is one of
    @returns          the count of findings with a command that `--fix` runs
    """
    return sum(1 for issue in issues if _offered(issue) and not refused(issue, issues)
               and in_kept(issue, kept, instances or {}))


def problems(issues: Sequence[Issue]) -> bool:
    """Return whether the findings call for action: something stops a move, or is broken

    @param issues  the findings
    @returns       True when the command's exit status is 1
    """
    return any(stops(issue) or issue.severity >= Severity.HIGH for issue in issues)


def _next(issues: Sequence[Issue], instances: dict[str, Instance], target: Instance | None) -> list[str]:
    """Return what to run after the report

    On a Mac with several installations, `doctor --fix` repairs the one that stays: without a `--target`, the
    choice comes first, and each installation that has fixes gets the command that makes them.

    @param issues     the findings
    @param instances  the installations by prefix
    @param target     the installation that `--target` says the user keeps, or None
    @returns          the lines; nothing when there is nothing to do next
    """
    chosen = keeps(target, instances) if target is not None else ""
    if target is not None or len(instances) < 2:
        count = fixable(issues, target, instances)
        if count:
            return [f"Next: {FIX}{chosen}   (it offers {counted(count, 'fix', 'fixes')})"]
    else:
        offers = [(inst, fixable(issues, inst, instances)) for inst in instances.values()]
        if any(count for _, count in offers):
            return (["Next: brew-ports recommend   (it compares a move in each direction)",
                     "Then the fixes of the installation you keep:"]
                    + [f"  {at(inst)}: {FIX}{keeps(inst, instances)}   (it offers {counted(count, 'fix', 'fixes')})"
                       for inst, count in offers if count])
    stopping = [issue for issue in issues if stops(issue) and not unchecked(issue)]
    if target is not None and stopping and all(_in_part(issue) for issue in stopping):
        return [f"Next: brew-ports plan{chosen}   (what is listed first stops only a part of the move; the plan "
                "says what it leaves)"]
    if stopping:
        return [f"Next: fix what is listed first, then brew-ports doctor{chosen}"]
    if len(instances) > 1:
        return [f"Next: brew-ports plan{chosen}" if target is not None else "Next: brew-ports recommend"]
    return []


def _in_part(issue: Issue) -> bool:
    """Return whether a finding stops only the uninstall of an installation, which a plan then leaves installed

    @param issue  a finding that stops something
    @returns      True when a plan goes ahead without that part
    """
    return issue.severity is not Severity.CRITICAL and set(issue.blocks) == {Blocks.REMOVE}


def closing(issues: Sequence[Issue], instances: Sequence[Instance], target: Instance | None = None) -> list[str]:
    """Return the last lines of the report: what to run next, and why the exit status is 1 when it is

    @param issues     the findings
    @param instances  the installations the scan found
    @param target     the installation that `--target` says the user keeps, or None
    @returns          the lines
    """
    lines = _next(issues, known(instances), target)
    return [""] + lines + unchanged(issues) if lines or problems(issues) else []


def unchanged(issues: Sequence[Issue]) -> list[str]:
    """Return the line that explains exit status 1, for a run that leaves the findings as they are

    @param issues  the findings
    @returns       the line when the findings call for action; nothing otherwise
    """
    return [EXIT_1] if problems(issues) else []


# doctor --fix ------------------------------------------------------------------------

def named(issue: Issue, instances: dict[str, Instance]) -> str:
    """Return a finding as `doctor --fix` names it

    @param issue      a finding
    @param instances  the installations by prefix
    @returns          its title, with its installation when the title does not name it
    """
    return issue.title + _where(issue, instances)


def offer(issue: Issue, instances: dict[str, Instance], first: Sequence[str] = (), how: str = "ask") -> list[str]:
    """Return the lines that present one fix: the finding, what `doctor --fix` does for it, what else to know

    @param issue      a finding that `doctor --fix` offers to fix
    @param instances  the installations by prefix
    @param first      what `doctor --fix` does before the fix's own commands, as words that follow `y `
    @param how        `ask` when a question follows; in a dry run `dry` for a fix that a question comes before
                      and `dry-yes` for one that `--yes` answers; `run` when the commands follow unasked
    @returns          the lines
    """
    steps = list(first) + [does(issue)]
    lines = [named(issue, instances)]
    if how == "ask" and len(steps) == 1:
        lines.append(f"  y {steps[0]}; n changes nothing.")
    elif how == "ask":
        lines += [f"  y {steps[0]},"] + [f"    then {step}," for step in steps[1:-1]]
        lines += [f"    then {steps[-1]}.", "  n changes nothing."]
    elif how in ("dry", "dry-yes"):
        lines.append(f"  doctor --fix {'asks, then ' if how == 'dry' else ''}{', then '.join(steps)}.")
    return lines + [f"  {line}" for line in fix_lines(issue) if not line.startswith(FIX_OFFER)]


def copy(kept: str, name: str, other: Instance, reasons: Sequence[str], next_step: str) -> str:
    """Return the warning under a repair whose package another installation has too

    @param kept       the package's name in the installation that stays
    @param name       its name in the other installation
    @param other      the other installation
    @param reasons    why the other copy is left to the move, each as the words that follow "it"; none for a
                      copy that can be uninstalled alone
    @param next_step  the command that uninstalls the other copy alone; with `reasons`, the `plan` command of
                      the move
    @returns          the line: that both are installed, what that means, and what to run once the repair worked
    """
    there = f"{kept} is also installed in {at(other)}" + ("" if name == kept else f", as {name}")
    broken = f"{there}. While both copies are installed, one of them is broken"
    if not reasons:
        return f"{broken}. Once this fix has worked, uninstall the other copy: {next_step}"
    return f"{broken}. Leave the other copy to the move, because it {series(reasons)}: {next_step}"


def together(issues: Sequence[Issue], instances: dict[str, Instance], asked: bool, yes: bool = False,
             notes: Sequence[Sequence[str]] = ()) -> list[str]:
    """Return the lines that present the fixes which take one answer for them all

    @param issues     the findings
    @param instances  the installations by prefix
    @param asked      whether the question follows, so the lines say what each answer does
    @param yes        whether `--yes` gives that answer
    @param notes      what else to know about each fix, in the order of the findings; none without it
    @returns          the lines
    """
    lines = [f"With --yes, these {len(issues)} fixes are made without a question:" if yes
             else f"These {len(issues)} fixes take one answer:"]
    for index, issue in enumerate(issues):
        lines += [f"  {named(issue, instances)}", f"      {does(issue)}"]
        lines += [f"      {note}" for note in (notes[index] if index < len(notes) else ())]
    return lines + (["  y makes them; n changes nothing."] if asked else [])


def nothing_to_fix(target: Instance | None, chosen: str) -> str:
    """Return the line of a `doctor --fix` run that has no fix to offer

    @param target  the installation that stays, or None
    @param chosen  the options that name it, as `keeps` gives them; none on a Mac with one installation
    @returns       the line
    """
    if target is None or not chosen:
        return NOTHING_TO_FIX
    return (f"No finding about {at(target)}, which you keep, has a fix that `doctor --fix` can make. "
            f"`brew-ports doctor{chosen}` lists what was found and what to do about it.")


def not_offered(issues: Sequence[Issue], instances: dict[str, Instance]) -> list[str]:
    """Return the lines that name the fixes which a `brew.env` file keeps `doctor --fix` from

    @param issues     the findings whose fix runs the `brew` of an installation with such a file
    @param instances  the installations by prefix
    @returns          why they are not offered, then each finding; nothing without one
    """
    if not issues:
        return []
    return ["", "Not offered, because a brew.env file changes the settings that brew-ports runs `brew` with "
            "(`brew-ports doctor` lists the lines to remove):"] + [f"  {named(issue, instances)}" for issue in issues]


def fix_opening(count: int, sudo: bool, dry_run: bool, yes: bool, tty: bool = True, *,
                chosen: str = "") -> list[str]:
    """Return the first lines of `doctor --fix`, which come before sudo asks for a password

    @param count    how many fixes it offers
    @param sudo     whether one of them needs the password
    @param dry_run  whether nothing is to change
    @param yes      whether `--yes` answers the questions
    @param tty      whether there is a terminal to ask on
    @param chosen   the options that name the installation that stays, as `keeps` gives them
    @returns        the lines
    """
    if yes:
        asks = ("--yes answers for you, except where a fix uninstalls a package or one of its versions, or deletes "
                "a cask's record or a stray file: that takes your own answer on a terminal")
    elif not tty and not dry_run:
        asks = f"There is no terminal to ask on, so it makes none of them: `{FIX}{chosen} --yes` answers for you"
    else:
        asks = "It asks before it changes anything"
    lines = [f"doctor --fix offers {counted(count, 'fix', 'fixes')}. {asks}. `brew-ports doctor{chosen}` lists "
             "everything that was found."]
    if sudo and not dry_run:
        lines.append(f"{'It needs' if count == 1 else 'Some of them need'} your password (sudo).")
    return lines


def rollback(undo: str) -> str:
    """Return how to put back what a fix of a `doctor --fix` run uninstalled

    @param undo  the run that saved what was installed before its first fix of that kind
    @returns     the line
    """
    return f"If a fix of this run uninstalled something you want back: brew-ports rollback {undo}"


def fix_stopped(run_folder: str, made: int, undo: str | None = None, chosen: str = "") -> list[str]:
    """Return the lines that follow the error of a fix that failed

    @param run_folder  the run folder, as the output names it
    @param made        how many fixes were made before
    @param undo        the run whose `rollback` puts back what a fix uninstalled; None when no fix came that far
    @param chosen      the options that name the installation that stays, as `keeps` gives them
    @returns           the lines, indented under the error
    """
    kept = f"The {'fix' if made == 1 else 'fixes'} made before it {'stays' if made == 1 else 'stay'}. " if made else ""
    return ([f"  Its whole output is in the folder `out` of the run folder, {run_folder}.",
             f"  {kept}Fix the cause, then run `{FIX}{chosen}` again."]
            + ([f"  {rollback(undo)}"] if undo else []))


def fix_closing(made: int, left: Sequence[Issue], undo: str | None, chosen: str = "") -> list[str]:
    """Return the last lines of `doctor --fix`: what it did, how to undo an uninstall, what to run next

    @param made    how many fixes it made
    @param left    the findings it did not fix
    @param undo    the run whose `rollback` puts back what a fix uninstalled; None when no fix came that far
    @param chosen  the options that name the installation that stays, as `keeps` gives them
    @returns       the lines
    """
    lines = ["", f"Made {counted(made, 'fix', 'fixes')}." if made else "Made no fix."]
    if undo:
        lines.append(rollback(undo))
    lines.append(f"Next: brew-ports doctor{chosen}   (it checks again and lists what is left)" if made
                 else f"Next: brew-ports doctor{chosen}   (it lists what was found)")
    return lines + unchanged(left)

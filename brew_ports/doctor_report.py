"""What `doctor` says: what it checked, what stops a move, the findings by what they mean, and what to run next"""

from __future__ import annotations

import os
from collections.abc import Sequence

from .model import Action, Blocks, Instance, Issue, Severity
from .report import FIX_OFFER, NOT_CHECKED, SCAN_REUSED, at, counted, place, series, some, typed

EVIDENCE_SHOWN = 3                  # evidence lines of one finding in the default report
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


def fix_lines(issue: Issue, blocked: bool = False) -> list[str]:
    """Return what to do about a finding: the fix `doctor --fix` makes, the commands for the user, the notes

    @param issue    a finding
    @param blocked  whether a `brew.env` file keeps `doctor --fix` from the finding's fix
    @returns        the lines, in the order of the remedies; a note is printed as its site worded it
    """
    lines: list[str] = []
    offered = issue.auto_fix or issue.confirm_each
    worded = _worded(issue) is not None
    for action in issue.remedies:
        if action.kind == "note":
            lines.append(BREW_ENV_FIRST if blocked and action.description.startswith(FIX_OFFER)
                         else action.description)
        elif action.manual:
            lines.append(f"{action.description}: {_command(action)}" if action.description
                         else f"Fix: {_command(action)}")
        elif not offered:
            lines.append(f"Fix: {_command(action)}")
        elif not worded and action is runs(issue)[0]:
            lines.append(BREW_ENV_FIRST if blocked else f"{FIX_OFFER}{does(issue)})")
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


def finding(issue: Issue, instances: dict[str, Instance], verbose: bool = False, blocked: bool = False) -> list[str]:
    """Return the lines of one finding: its title, what was found, what it stops, what to do

    The title is a sentence that names the finding's subject. Outside the group of its own installation, a
    finding whose title does not name that installation gets it appended.

    @param issue      a finding
    @param instances  the installations by prefix
    @param verbose    whether to print the finding's name and every evidence line
    @param blocked    whether a `brew.env` file keeps `doctor --fix` from the finding's fix
    @returns          the lines, indented for the report
    """
    inst = instances.get(issue.instance_prefix or "")
    own = inst is not None and heading(issue, instances) == UPKEEP % at(inst)
    lines = [f"  {issue.title}{'' if own else _where(issue, instances)}" + (f"   [{issue.code}]" if verbose else "")]
    lines += _evidence(issue, verbose)
    if stops(issue):
        lines.append(f"      {stopped(issue, instances)}")
    return lines + [f"      {line}" for line in fix_lines(issue, blocked)]


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


def several(issues: Sequence[Issue], blocked: bool = False) -> list[str]:
    """Return the lines of several findings of one kind in one installation

    @param issues   the findings, which share a name that `SEVERAL` words
    @param blocked  whether a `brew.env` file keeps `doctor --fix` from their fixes
    @returns        what they share and what each is about, then what to do about them
    """
    first = issues[0]
    names = list(dict.fromkeys(_name(i) for i in issues))
    one, many = SEVERAL[first.code]
    lines = [f"  {one if len(names) == 1 else many.format(count=len(names))}: {some(names)}"]
    shared = [line for line in fix_lines(first, blocked) if all(line in fix_lines(i, blocked) for i in issues[1:])
              and not line.startswith(FIX_OFFER)]
    if _offered(first) and not blocked:
        worded = _worded(first) if all(_worded(i) == _worded(first) for i in issues) else None
        shared.insert(0, f"Fix: brew-ports doctor --fix (asks about each{', then ' + worded if worded else ''})")
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
           reused: bool = False, verbose: bool = False, scan_notes: Sequence[str] = ()) -> list[str]:
    """Return the text report of `doctor`

    @param issues      the findings, sorted
    @param instances   the installations the scan found
    @param notes       the checks that the detectors could not run
    @param reused      whether the findings come from a recent scan
    @param verbose     whether to print every finding on its own, with its name and all its evidence
    @param scan_notes  what the scan noted, which only a verbose report prints
    @returns           the report lines
    """
    by_prefix = known(instances)
    lines = [checked(instances)] + ([SCAN_REUSED] if reused else []) + ["", verdict(issues, by_prefix)]
    for name, found in groups(issues, by_prefix):
        lines += ["", f"{name} ({len(found)})"]
        # Findings of one kind in one installation that `doctor --fix` offers print as one, the rest as another.
        kinds: dict[tuple[str, str | None, bool, bool], list[Issue]] = {}
        for issue in found:
            key = (issue.code, issue.instance_prefix, _offered(issue), refused(issue, issues))
            kinds.setdefault(key, []).append(issue)
        for (code, _, _, blocked), same in kinds.items():
            if len(same) > 1 and code in SEVERAL and not verbose:
                lines += several(same, blocked)
            else:
                for issue in same:
                    lines += finding(issue, by_prefix, verbose, blocked)
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


def fixable(issues: Sequence[Issue]) -> int:
    """Return how many findings `doctor --fix` offers to fix

    @param issues  the findings
    @returns       the count of findings with a command that `--fix` runs
    """
    return sum(1 for issue in issues if _offered(issue) and not refused(issue, issues))


def problems(issues: Sequence[Issue]) -> bool:
    """Return whether the findings call for action: something stops a move, or is broken

    @param issues  the findings
    @returns       True when the command's exit status is 1
    """
    return any(stops(issue) or issue.severity >= Severity.HIGH for issue in issues)


def closing(issues: Sequence[Issue], several_installations: bool) -> list[str]:
    """Return the last lines of the report: what to run next, and why the exit status is 1 when it is

    @param issues                 the findings
    @param several_installations  whether there is anything to move
    @returns                      the lines
    """
    count = fixable(issues)
    if count:
        lines = [f"Next: brew-ports doctor --fix   (it offers {counted(count, 'fix', 'fixes')})"]
    elif any(stops(issue) and not unchecked(issue) for issue in issues):
        lines = ["Next: fix what is listed first, then brew-ports doctor"]
    elif several_installations:
        lines = ["Next: brew-ports recommend"]
    else:
        lines = []
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


def together(issues: Sequence[Issue], instances: dict[str, Instance], asked: bool, yes: bool = False) -> list[str]:
    """Return the lines that present the fixes which take one answer for them all

    @param issues     the findings
    @param instances  the installations by prefix
    @param asked      whether the question follows, so the lines say what each answer does
    @param yes        whether `--yes` gives that answer
    @returns          the lines
    """
    lines = [f"With --yes, these {len(issues)} fixes are made without a question:" if yes
             else f"These {len(issues)} fixes take one answer:"]
    for issue in issues:
        lines += [f"  {named(issue, instances)}", f"      {does(issue)}"]
    return lines + (["  y makes them; n changes nothing."] if asked else [])


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


def fix_opening(count: int, sudo: bool, dry_run: bool, yes: bool, tty: bool = True) -> list[str]:
    """Return the first lines of `doctor --fix`, which come before sudo asks for a password

    @param count    how many fixes it offers
    @param sudo     whether one of them needs the password
    @param dry_run  whether nothing is to change
    @param yes      whether `--yes` answers the questions
    @param tty      whether there is a terminal to ask on
    @returns        the lines
    """
    if yes:
        asks = ("--yes answers for you, except where a fix uninstalls a package or one of its versions, or deletes "
                "a cask's record or a stray file: that takes your own answer on a terminal")
    elif not tty and not dry_run:
        asks = ("There is no terminal to ask on, so it makes none of them: `brew-ports doctor --fix --yes` answers "
                "for you")
    else:
        asks = "It asks before it changes anything"
    lines = [f"doctor --fix offers {counted(count, 'fix', 'fixes')}. {asks}. `brew-ports doctor` lists everything "
             "that was found."]
    if sudo and not dry_run:
        lines.append(f"{'It needs' if count == 1 else 'Some of them need'} your password (sudo).")
    return lines


def rollback(undo: str) -> str:
    """Return how to put back what a fix of a `doctor --fix` run uninstalled

    @param undo  the run that saved what was installed before its first fix of that kind
    @returns     the line
    """
    return f"If a fix of this run uninstalled something you want back: brew-ports rollback {undo}"


def fix_stopped(run_folder: str, made: int, undo: str | None = None) -> list[str]:
    """Return the lines that follow the error of a fix that failed

    @param run_folder  the run folder, as the output names it
    @param made        how many fixes were made before
    @param undo        the run whose `rollback` puts back what a fix uninstalled; None when no fix came that far
    @returns           the lines, indented under the error
    """
    kept = f"The {'fix' if made == 1 else 'fixes'} made before it {'stays' if made == 1 else 'stay'}. " if made else ""
    return ([f"  Its whole output is in the folder `out` of the run folder, {run_folder}.",
             f"  {kept}Fix the cause, then run `brew-ports doctor --fix` again."]
            + ([f"  {rollback(undo)}"] if undo else []))


def fix_closing(made: int, left: Sequence[Issue], undo: str | None) -> list[str]:
    """Return the last lines of `doctor --fix`: what it did, how to undo an uninstall, what to run next

    @param made  how many fixes it made
    @param left  the findings it did not fix
    @param undo  the run whose `rollback` puts back what a fix uninstalled; None when no fix came that far
    @returns     the lines
    """
    lines = ["", f"Made {counted(made, 'fix', 'fixes')}." if made else "Made no fix."]
    if undo:
        lines.append(rollback(undo))
    lines.append("Next: brew-ports doctor   (it checks again and lists what is left)" if made
                 else "Next: brew-ports doctor   (it lists what was found)")
    return lines + unchanged(left)

"""What `apply` says around its phases: the opening lines, the headings, the questions and the closing lines"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from typing import Any

from . import plan_report, report
from .model import Instance, Plan
from .plan_phases import PHASE_NAMES
from .report import at, counted, manager_name, place, series, some, tilde

QUESTIONS = {2: "Run these repairs?", 3: "Install the replacements?", 5: "Uninstall the old packages?",
             7: "Make these changes?"}
NEW_PLAN = "make a new plan with `brew-ports plan`"
MAKE_NEW_PLAN = "  Make a new plan with `brew-ports plan`, then apply that."
RESUME = "brew-ports apply --resume %s"
STOPS_HERE = f"n stops the run here; `{RESUME}` continues it."
NOTHING_STOPS = "A fresh scan of this Mac found nothing that stops the move."
GATE = "every replacement is installed, provides commands and finds its libraries"
FROM_PLAN = "This list is from the plan. It is made again when the phase runs: what is gone by then is skipped."
ERROR_WIDTH = 110                   # a failed command longer than this is cut in the error that names it


def resume(run_id: str) -> str:
    """Return the command that continues a run

    @param run_id  the run's id
    @returns       the command, as the user types it
    """
    return RESUME % run_id


def _instances(plan: Plan) -> dict[str, Instance]:
    """Return the installations a plan records, by prefix

    @param plan  the plan
    @returns     the target and the old installations as the plan found them
    """
    return {inst.prefix: inst for inst in plan.instances}


def named(plan: Plan, prefixes: Sequence[str]) -> str:
    """Return installations as a sentence names them

    @param plan      the plan, which records the installations
    @param prefixes  the prefixes of some of them
    @returns         such as `MacPorts at /opt/local and Homebrew at /usr/local`; a prefix the plan does not record
                     stands for itself
    """
    known = _instances(plan)
    return series(at(known[prefix]) if prefix in known else prefix for prefix in prefixes)


def _fate(plan: Plan, inst: Instance | None, prefix: str, removed: Sequence[str]) -> str:
    """Return what the run does to one old installation

    @param plan     the plan
    @param inst     the installation, or None when the plan does not record it
    @param prefix   its prefix
    @param removed  the prefixes of the old installations phase 6 uninstalls
    @returns        its packages to uninstall, and whether it goes or stays
    """
    if prefix in plan.path_removed:
        return "deleted whole, with its packages"
    kinds = [kind for kind, _ in plan.removal_set.get(prefix, []) if kind != "cask-adopted"]
    what = f"{report.by_kind(kinds)} to uninstall" if kinds else "nothing to uninstall"
    if prefix in removed:
        return f"{what}, then {manager_name(inst) if inst is not None else 'the manager'} itself"
    return f"{what}; it stays installed"


def preview(plan: Plan, actions: Sequence[Any], prefixes: Sequence[str]) -> list[str]:
    """Return the plan's preview of phase 6: what is saved, what is deleted, what else goes and what stays

    @param plan      the plan
    @param actions   the preview actions of phase 6
    @param prefixes  the prefixes of the old installations phase 6 uninstalls
    @returns         the lines, the last of which says that the run makes the list again; none for an empty preview
    """
    lines = []
    for prefix in prefixes:
        mine = [action for action in actions if action.instance_prefix == prefix]
        if len(prefixes) > 1:
            lines.append(f"  {named(plan, [prefix])}:")
        saved, deleted = plan_report.saved_and_deleted(mine)
        if saved:
            lines.append(f"  Save in the run folder: {some(saved, plan_report.PATHS_SHOWN)}")
        if deleted:
            lines.append(f"  Then delete: {some(deleted, plan_report.PATHS_SHOWN)}")
        notes = [a.description for a in mine if a.kind == "note" and not a.action_id.endswith(".checks")]
        lines += [f"  {note[:1].upper()}{note[1:]}" for note in notes]
    return lines + [f"  {FROM_PLAN}"] if lines else []


def opening(plan: Plan, removed: Sequence[str], run_folder: str, dry_run: bool) -> list[str]:
    """Return the first lines of a run: what moves where, what becomes of each old installation, the run folder

    @param plan        the plan
    @param removed     the prefixes of the old installations phase 6 uninstalls
    @param run_folder  the run folder
    @param dry_run     whether the run changes nothing, which the first line then says
    @returns           the lines; a dry run names no run folder, because its run cannot be continued
    """
    known = _instances(plan)
    target = known.get(plan.target_prefix)
    into = place(target) if target is not None else plan.target_prefix
    moved = len(plan.mappings)
    lines = ["Dry run: nothing will change."] if dry_run else []
    lines.append(f"Moving {counted(moved, 'package')} into {into}" if moved else f"No package moves into {into}")
    for prefix in plan.source_prefixes:
        inst = known.get(prefix)
        lines.append(f"  from {place(inst) if inst is not None else prefix}: {_fate(plan, inst, prefix, removed)}")
    return lines if dry_run else lines + [f"Run folder: {tilde(run_folder)}"]


def continuing(run_id: str, done: int | None, run_folder: str) -> list[str]:
    """Return the first lines of a resumed run

    @param run_id      the run's id
    @param done        the last phase an earlier start finished, or None when none finished
    @param run_folder  the run folder
    @returns           the lines
    """
    after = f" after phase {done}" if done is not None else " from its start"
    return [f"Continuing run {run_id}{after}.", f"Run folder: {tilde(run_folder)}"]


def heading(number: int, plan: Plan, removed: Sequence[str]) -> str:
    """Return the heading of a phase

    @param number   the phase number
    @param plan     the plan
    @param removed  the prefixes of the old installations phase 6 uninstalls
    @returns        such as `Phase 3  Install the replacements`; phases 2 and 6 name their installations
    """
    if number == 2:
        name = f"Repair {named(plan, [plan.target_prefix])}"
    elif number == 6 and removed:
        name = f"Uninstall {named(plan, removed)}"
    else:
        name = PHASE_NAMES.get(number, "").capitalize()
    return f"Phase {number}  {name}"


def tasks(todo: Sequence[str], dry_run: bool = False) -> list[str]:
    """Return what is left for the user to do, each task once

    @param todo     the tasks
    @param dry_run  whether the run only previews, so the tasks come after the real run
    @returns        a heading and the tasks; nothing without tasks
    """
    if not todo:
        return []
    return ["For you to do after the run:" if dry_run else "For you to do:"] + [f"  {task}" for task in todo]


def leftovers(plan: Plan, removed: Sequence[str], run_id: str, todo: Sequence[str]) -> list[str]:
    """Return what a run that ends leaves with the user: the hand tasks, the undo command and the report

    @param plan     the plan
    @param removed  the prefixes of the old installations phase 6 uninstalled
    @param run_id   the run's id
    @param todo     what is left for the user to do
    @returns        the lines
    """
    undo = f"Undo: brew-ports rollback {run_id}"
    if removed:
        known = _instances(plan)
        names = series(dict.fromkeys(manager_name(known[p]) if p in known else p for p in removed))
        undo += f"   (says how to reinstall {names} first; run again, it puts back what was uninstalled)"
    else:
        undo += "   (puts back what was uninstalled; the replacements stay)"
    return tasks(todo) + [undo, "Report: report.md in the run folder, with every command that ran in commands.log."]


def finished(plan: Plan, removed: Sequence[str], run_id: str, todo: Sequence[str],
             newer: tuple[int, str] | None = None) -> list[str]:
    """Return the closing lines of a run that finished: what was done, what is left to the user, undo, next

    @param plan     the plan
    @param removed  the prefixes of the old installations phase 6 uninstalled
    @param run_id   the run's id
    @param todo     what is left for the user to do, each task once
    @param newer    how many packages of the target have a newer version that the move did not install, with the
                    command that upgrades them; None when there is nothing to say of that
    @returns        the lines
    """
    moved = len(plan.mappings)
    done = [f"{counted(moved, 'package')} moved into {named(plan, [plan.target_prefix])}"] if moved else []
    for prefix in plan.source_prefixes:
        kinds = [kind for kind, _ in plan.removal_set.get(prefix, []) if kind != "cask-adopted"]
        if prefix in removed:
            done.append(f"{named(plan, [prefix])} uninstalled")
        elif kinds:
            done.append(f"{report.by_kind(kinds)} uninstalled from {named(plan, [prefix])}")
    upgrade = []
    if newer is not None:
        count, command = newer
        upgrade = [f"{counted(count, 'package')} of {named(plan, [plan.target_prefix])} "
                   f"{'has' if count == 1 else 'have'} a newer version, which this move did not install. To upgrade "
                   f"{'it' if count == 1 else 'them'}: {command}"]
    return (["", f"Finished: {'; '.join(done)}." if done else "Finished."] + leftovers(plan, removed, run_id, todo)
            + upgrade
            + ["Next: open a new Terminal window, which finds the moved commands and reads any edited shell file."])


def dry_finished(plan_file: str | None, run_id: str | None, todo: Sequence[str] = ()) -> list[str]:
    """Return the closing lines of a dry run

    @param plan_file  the plan as the user named it, or None for a dry run of `--resume`
    @param run_id     the resumed run's id, or None
    @param todo       what the run will leave for the user to do
    @returns          the lines
    """
    command = f"--resume {run_id}" if plan_file is None else shlex.quote(plan_file)
    return ["", "Dry run finished: nothing was changed."] + tasks(todo, True) + [f"Next: brew-ports apply {command}"]


def stops_here(run_id: str) -> str:
    """Return the line above a phase's question that says what a no does

    @param run_id  the run's id
    @returns       the line
    """
    return STOPS_HERE % run_id


def declined(number: int, run_id: str) -> list[str]:
    """Return what a no to a phase's question leaves the user with

    @param number  the phase number
    @param run_id  the run's id
    @returns       the line: the run stopped before the phase, and the command that continues it
    """
    return [f"Stopped before phase {number}, as you answered. Continue with: {resume(run_id)}"]


def unanswered(number: int, run_id: str) -> list[str]:
    """Return the error of a phase whose question nobody can answer: no terminal, and no `--yes`

    @param number  the phase number
    @param run_id  the run's id
    @returns       the error, then what to run
    """
    return [f"phase {number} asks before it changes anything, and there is no terminal to ask on",
            f"  Run it in a Terminal window, or answer yes to every question: {resume(run_id)} --yes"]


def stopped_after(number: int, limit: int, run_id: str, dry_run: bool) -> list[str]:
    """Return the closing lines of a run that `--stop-after` ended

    @param number   the last phase that ran
    @param limit    the `--stop-after` value
    @param run_id   the run's id
    @param dry_run  whether the run changes nothing
    @returns        the lines; a real run names the command that continues it
    """
    if dry_run:
        return ["", f"Dry run stopped after phase {number} (--stop-after {limit}): nothing was changed."]
    return ["", f"Stopped after phase {number} (--stop-after {limit}). Continue with: {resume(run_id)}"]


def password(reasons: Sequence[str], dry_run: bool) -> str:
    """Return why sudo is needed, which a run says before sudo asks for the password

    @param reasons  what needs it, each as a verb and its object
    @param dry_run  whether the run only previews
    @returns        the line
    """
    needs = "The run will need your password (sudo) to" if dry_run else "Your password is needed (sudo) to"
    return f"{needs} {series(reasons)}."


def record(dry_run: bool) -> str:
    """Return what phase 1 saves for undo

    @param dry_run  whether the run only previews
    @returns        the line
    """
    what = "what is installed, your shell files and your service files in the run folder, for `brew-ports rollback`"
    return f"{'Would save' if dry_run else 'Saved'} {what}."


def failed(result: Any) -> str:
    """Return the statement of a command that failed

    @param result  the command's result
    @returns       the command as the user would type it, cut when long, its exit status and its error line
    """
    text = result.typed or result.action_id
    if len(text) > ERROR_WIDTH:
        text = text[:ERROR_WIDTH].rsplit(" ", 1)[0] + " ..."
    line = result.error_line()
    return f"`{text}` failed (exit {result.exit})" + (f": {line}" if line else "")

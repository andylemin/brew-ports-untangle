"""`brew-ports apply`: a new or resumed run takes a plan through phases 0 to 8

Phases 2 and 3 live in `exec_install`, phase 5 in `exec_remove`, phase 7 in `exec_env`, the others here.
"""

from __future__ import annotations

import json
import os
import shlex
from collections.abc import Callable, Mapping

from . import apply_report, doctor, exec_env, exec_install, exec_remove, model, scan, snapshot, state, system
from .apply_report import MAKE_NEW_PLAN, NEW_PLAN
from .context import Context
from .exec_run import (DECLINED, EXIT_ACTION, EXIT_OK, EXIT_PREFLIGHT, EXIT_USAGE, EXIT_VERIFY, PLAN_FILE, SOURCE_BIN,
                       START, Run, Stop, module, phase6_prefixes)
from .homebrew import actions as brew_actions
from .model import Instance, Manager, Plan, is_recorded_as
from .report import COMMAND_OF, at, counted, series, some, tilde, typed
from .runner import ActionFailed, BaseRunner, EscalationFailed, Interrupted, PreflightError, command_runner

# Phase 0 -------------------------------------------------------------------------------------

def plan_context(run: Run) -> doctor.PlanContext:
    """Return the plan as the blocking rule weighs it, in the fresh scan's prefixes

    A source whose phase 6 deletion has begun is exempt.

    @param run  the run, after its phase 0 scan
    @returns    the target, uninstall, cask, remove and exempt prefixes
    """
    plan = run.plan
    pairs = list(plan.removal_set.items()) + list(plan.path_removed.items())
    casks = sorted({p for p, ps in pairs if any(kind in ("cask", "cask-adopted") for kind, _ in ps)})
    exempt = [p for p in list(plan.source_prefixes) + phase6_prefixes(plan) if run.phase6_begun(p)]
    return doctor.PlanContext(
        target_prefix=run.fresh_prefix(plan.target_prefix),
        uninstall_prefixes=tuple(run.fresh_prefix(p) for p, ps in sorted(plan.removal_set.items()) if ps),
        cask_prefixes=tuple(run.fresh_prefix(p) for p in casks),
        remove_prefixes=tuple(run.fresh_prefix(p) for p in run.removed),
        exempt_prefixes=tuple(run.fresh_prefix(p) for p in exempt))


def blocking_lines(run: Run) -> list[str]:
    """Return the findings that stop this plan (exit 3), each with its fixes

    Low disk space does not count in a resumed run past phase 3, whose own installs used the space.

    @param run  the run, with the findings of its phase 0 scan
    @returns    the lines to print; empty when nothing stops the plan
    """
    found = doctor.blocking(run.issues, plan_context(run))
    if run.resumed and run.past(3):
        found = [i for i in found if i.code != "system-low-disk-space"]
    lines = doctor.blocked_by_lines(found, run.bundle.result.instances if run.bundle is not None else run.instances)
    if any((i.auto_fix or i.confirm_each) and any(not a.manual for a in i.remedies) for i in found):
        lines.append(f"  After `brew-ports doctor --fix`, {NEW_PLAN}.")
    return lines


def _repairs(run: Run, inst: Instance) -> str:
    """Return how to repair an installation whose command cannot run: `doctor --fix` when it has a fix, else `doctor`

    @param run   the run, with the findings of its phase 0 scan
    @param inst  the installation
    @returns     the advice under the installation's line
    """
    fixable = any(i.instance_prefix == inst.prefix and (i.auto_fix or i.confirm_each) and i.remedies
                  for i in run.issues)
    if fixable:
        return f"`brew-ports doctor --fix` can repair it; {NEW_PLAN} afterwards."
    return f"`brew-ports doctor` says what is wrong with it; {NEW_PLAN} once it is repaired."


def drivability_lines(run: Run) -> list[str]:
    """Return why the plan cannot use the target, or an old installation it uninstalls from with its command

    An old installation whose phase 6 deletion has begun is exempt.

    @param run  the run, after its phase 0 scan
    @returns    a statement per installation that is gone or whose command cannot run, each with what to do
    """
    plan = run.plan
    wanted = [(plan.target_prefix, "installs into")]
    for prefix, pairs in sorted(plan.removal_set.items()):
        if any(kind != "cask-adopted" for kind, _ in pairs) and not run.phase6_begun(prefix):
            wanted.append((prefix, "uninstalls from"))
    lines = []
    for prefix, does in wanted:
        inst = run.fresh_instance(prefix)
        if inst is None:
            lines += [f"the plan {does} {prefix}, where no Homebrew or MacPorts is found any more", MAKE_NEW_PLAN]
        elif not inst.drivable:
            detail = f": {inst.usability_detail}" if inst.usability_detail else ""
            lines += [f"{at(inst)}: its `{COMMAND_OF[inst.manager]}` command cannot run{detail}",
                      "  " + _repairs(run, inst)]
    return lines


def refused_lines(run: Run) -> list[str]:
    """Return the plan's Homebrew targets that the catalogue refuses on the day of the apply

    @param run  the run, after its phase 0 scan
    @returns    one line per refused formula or cask; empty for a MacPorts target or without a catalogue
    """
    plan = run.plan
    target = run.fresh_instance(plan.target_prefix)
    if plan.target is not Manager.BREW or target is None:
        return []
    catalogue = run.bundle.catalogue(target.prefix)
    if catalogue is None:
        run.say("  Could not check whether Homebrew has disabled a replacement: its package list is missing.")
        return []
    lines = []
    seen: set[tuple[str, str]] = set()
    for m in plan.mappings:
        names = [(m.target_kind, m.target_name)] if m.target_kind in ("formula", "cask") and m.target_name else []
        names += [("formula", c) for c in m.companions]
        for kind, name in names:
            if (kind, name) in seen:
                continue
            seen.add((kind, name))
            why = catalogue.refused(name, kind)
            if why:
                swap = why.get("replacement_formula") or why.get("replacement_cask")
                hint = f" `--replace {m.source.name}={swap}` takes the one Homebrew names instead." if swap else ""
                lines += [f"Homebrew has disabled {kind} {name} (since {why.get('date')}: {why.get('because')}), "
                          "which the plan installs", MAKE_NEW_PLAN + hint]
    return lines


def sudo_reasons(run: Run) -> list[str]:
    """Return what the run needs sudo for, so phase 0 can say it before `sudo -v` asks for the password

    A line of an old installation in `/etc/paths` counts, because phase 7 may rewrite that file.

    @param run  the run, after its phase 0 scan
    @returns    the reasons, each a verb and its object; empty when no phase of the run calls sudo
    """
    plan = run.plan
    reasons = []
    target = run.target
    starts = plan.options.get("start_services") == "true"
    if any(a.sudo for n in (2, 3) for a in run.actions(n)) or (plan.target is Manager.PORTS and (
            plan.target_upgrades or starts or any(m.selections for m in plan.mappings))):
        reasons.append(f"change {at(target) if target is not None else plan.target_prefix}")
    if not snapshot.is_complete(run.run_dir) and any(
            inst.manager is Manager.PORTS and inst.drivable and "snapshot" in inst.features
            for inst in snapshot_instances(run)):
        reasons.append("save MacPorts' record of what is installed")
    if any(pairs and (inst := run.instance(prefix)) is not None and inst.manager is Manager.PORTS
           for prefix, pairs in plan.removal_set.items()):
        reasons.append("uninstall ports")
    if any(s.scope == "system" or s.domain == "system" for s in exec_remove.selected_services(run)):
        reasons.append("stop a system service")
    if exec_remove.shell_switch(run) is not None:
        reasons.append("change your login shell")
    if run.removed:
        reasons.append(f"uninstall {apply_report.named(plan, run.removed)}")
    sources = {run.fresh_prefix(p) for p in plan.source_prefixes}
    for line in run.bundle.result.environment.get("etc_paths") or []:
        entry = (line or {}).get("entry") or {}
        if not line.get("stock") and entry.get("instance_prefix") in sources and "edit /etc/paths" not in reasons:
            reasons.append("edit /etc/paths")
    return reasons


def record_source_bin(run: Run) -> None:
    """Record the `bin` listing of every source prefix at the first start, before anything is removed

    Phase 7 sets a selection only for commands a source had there.

    @param run  the run, in phase 0
    """
    path = run.run_dir.sub(SOURCE_BIN)
    plan = run.plan
    if run.dry_run or os.path.exists(path) or plan.target is not Manager.PORTS \
            or not any(m.selections for m in plan.mappings):
        return
    listing: dict[str, list[str]] = {}
    for prefix in plan.source_prefixes:
        try:
            listing[prefix] = sorted(os.listdir(os.path.join(prefix, "bin")))
        except OSError:
            listing[prefix] = []
    run.run_dir.write_json(SOURCE_BIN, json.dumps(listing, indent=2, sort_keys=True))


def preflight(run: Run) -> None:
    """Run phase 0: the checks that refuse a run, then `sudo -v`

    Nothing on the host changes and the dirty marker is not touched.

    @param run    the run
    @throws Stop  exit 3 when the tool runs as root, a finding blocks the plan, an instance cannot be driven,
                  Homebrew refuses a target or the first sudo keepalive fails
    """
    if system.running_as_root():
        raise Stop(EXIT_PREFLIGHT, [system.ROOT_MESSAGE])
    bundle = run.fresh_scan()
    if not run.dry_run:
        scan.write(bundle, run.run_dir)
    run.issues = doctor.detect_all(bundle, run.runner)
    lines = blocking_lines(run) + drivability_lines(run) + refused_lines(run)
    if lines:
        if run.resumed and any("doctor --fix" in line for line in lines):
            lines.append("  This run cannot be continued after `doctor --fix`: the new plan starts a new run.")
        raise Stop(EXIT_PREFLIGHT, lines)
    run.say("  " + apply_report.NOTHING_STOPS)
    record_source_bin(run)
    reasons = sudo_reasons(run)
    if reasons:
        run.say("  " + apply_report.password(reasons, run.dry_run))
    if run.dry_run or not reasons:
        return
    run.runner.sudo_preflight()
    run.runner.keepalive(force=True)
    if run.runner.keepalive_failed:
        raise Stop(EXIT_PREFLIGHT, [
            "sudo did not keep your password, so the commands that need it cannot run",
            "  Check `timestamp_timeout` in the sudoers file: 0 makes sudo ask before every command."])


# Phase 1 -------------------------------------------------------------------------------------

def snapshot_instances(run: Run) -> list[Instance]:
    """Return the instances phase 1 snapshots: the target and every source the fresh scan finds

    @param run  the run, after its phase 0 scan
    @returns    the fresh instances, in scan order
    """
    wanted = [run.plan.target_prefix] + list(run.plan.source_prefixes)
    return [inst for inst in run.fresh if any(is_recorded_as(inst, p) for p in wanted)]


def rc_files(bundle) -> list[str]:
    """Return the rc files of the shell analysis, which the environment cleanup may edit

    @param bundle  the fresh scan
    @returns       the paths of the files that exist
    """
    files = bundle.result.environment.get("files") or []
    return [f["path"] for f in files if isinstance(f, dict) and f.get("exists") and f.get("path")]


def snapshot_phase(run: Run) -> None:
    """Run phase 1, skipped as a whole once its completion marker exists

    Its files record the Mac before the run, so a resume never takes them again. It asks nothing and leaves the
    dirty marker alone: it uninstalls and deletes nothing, so a plan stays good after it.

    @param run  the run
    """
    if snapshot.is_complete(run.run_dir):
        return
    if run.dry_run:
        run.say("  " + apply_report.record(True))
        return
    with run.unmarked():
        written = snapshot.write(run.runner, run.run_dir, run.bundle, snapshot_instances(run),
                                 rc_files=rc_files(run.bundle), id_prefix="1", uid=run.uid)
    run.say("  " + apply_report.record(False))
    for line in snapshot.outcome(written):
        run.say("  " + line)


# Phase 4 -------------------------------------------------------------------------------------

def recovery_lines(run: Run, result) -> list[str]:
    """Return what the user can do after a failed gate

    @param run     the run
    @param result  the gate's result
    @returns       the command that continues the run, the plan that leaves the failed packages where they are,
                   and the undo of a run that repaired something
    """
    roots: list[str] = []
    for m in run.plan.mappings:
        subjects = {f"{m.source.name} -> {m.target_name}", m.source.name, m.target_name or ""} | set(m.companions)
        if any(f.subject in subjects for f in result.failures) and m.source.name not in roots:
            roots.append(m.source.name)
    run_id = run.run_dir.run_id
    lines = [f"  Fix what the lines above name, then continue with: {apply_report.resume(run_id)}"]
    if roots:
        lines.append(f"  Or leave those packages where they are: make the plan again with `--leave {','.join(roots)}` "
                     "added.")
    if run.actions(2):
        lines.append(f"  Or put back what the repairs of phase 2 uninstalled: brew-ports rollback {run_id}")
    return lines


def keep_tasks(run: Run, tasks: Mapping[str, str], say: bool = False) -> None:
    """Keep the packages that an upgrade of `--upgrade-all` left broken as tasks for the user

    The move does not need them, so the run goes on. Each start of a run finds them again in its own checks,
    so a package repaired between two starts is no task of the second. A package has one task: the wording of
    a later check, whose command fits the Mac as it is by then, takes the place of an earlier one.

    @param run    the run
    @param tasks  what the user has to do, by package, as the check worded it
    @param say    print each task of a package that had none, where the lines of the check do not show it
    """
    for package, task in tasks.items():
        earlier = run.repairs.get(package)
        run.repairs[package] = task
        if earlier is None:
            run.todo.append(task)
            if say:
                run.say(f"  For you to do after the run: {task}")
        elif earlier in run.todo:
            run.todo[run.todo.index(earlier)] = task


def gate(run: Run) -> None:
    """Run phase 4, `verify.check(gate=True)` over a fresh inventory

    A failure stops the run with exit 4 before any source package is removed; no flag lets a root through
    without its replacement.

    @param run    the run
    @throws Stop  exit 4 when the gate fails
    """
    if run.dry_run:
        run.say(f"  Would check that {apply_report.GATE}.")
        run.say("  No old package is uninstalled unless this passes.")
        return
    bundle = run.fresh_scan()
    result = module("verify").check(bundle, run.plan, run.runner, gate=True, run_dir=run.run_dir)
    if result.ok:
        run.say(f"  Passed: {apply_report.GATE}.")
        keep_tasks(run, result.tasks, say=True)
        return
    keep_tasks(run, result.tasks)
    for failure in result.failures:
        run.say("  " + failure.line())
    run.journal({"action_id": "4.gate", "kind": "note", "failures": [f.line() for f in result.failures]})
    begun = any(entry.get("phase") == 5 for entry in run.entries)      # an earlier start uninstalled already
    raise Stop(EXIT_ACTION, ["the check of the replacements failed" + (
        ", so nothing more is uninstalled" if begun else ", so no old package was uninstalled")]
        + recovery_lines(run, result))


# Phase 6 -------------------------------------------------------------------------------------

def remove_managers(run: Run) -> None:
    """Run phase 6 for every old installation the plan uninstalls

    `remove_manager` recomputes its lists and checks, and asks its own confirmations through `ctx`. A no to the
    phase's own question leaves the managers installed and lets the run go on; the journal keeps the answer, so a
    resume does not ask again.

    @param run                      the run
    @throws remove_manager.Stopped  a check, an archive or a deletion stopped phase 6; its lines join the report
    @throws Stop                    exit 4 when no terminal can answer the question and `--yes` is not given
    """
    named = [p for p in run.plan.options.get("remove_manager", "").split(",") if p]
    if not named:
        return
    several = len(named) > 1
    names = series(at(inst) if (inst := run.instance(p)) is not None else p for p in named)
    stays = f"  {names} {'stay' if several else 'stays'} installed, as you answered"
    if run.managers_stay:
        run.say(stays + ".")
        return
    if run.dry_run or not run.ctx.yes:
        phase = run.phase(6)
        for line in apply_report.preview(run.plan, phase.actions if phase else [], named):
            run.say(line)
    if run.dry_run:
        return
    it, its = ("them", "their") if several else ("it", "its")
    if run.asks:
        run.say(f"  To undo this later, reinstall {it} first; `brew-ports rollback` then puts {its} packages back.")
        run.say("  What is saved stays in the run folder, for you to copy back.")
    whole = any(prefix in run.plan.path_removed for prefix in named)     # nothing was uninstalled from it
    left = f"with what is still in {it}" if whole else f"without {its} packages"
    if not run.agreed(6, f"Uninstall {names}?", f"n leaves {names} installed, {left}, and the run goes on."):
        if not run.ctx.tty:
            raise run.unconfirmed(6)
        run.journal({"action_id": DECLINED, "kind": "note", "prefixes": named})
        run.declined = True
        run.say(f"{stays}; a new plan can uninstall {it} later.")
        return
    run.flush()
    bundle = run.fresh_scan()                     # the host as phase 5 left it
    # remove_manager prints its lines as it makes them; they are kept here for report.md only.
    remove_manager = module("remove_manager")
    try:
        lines = remove_manager.run(run.runner, run.run_dir, run.plan, bundle, run.ctx, resumed=run.resumed)
    except remove_manager.Stopped as exc:
        run.lines.extend(exc.lines)
        raise
    run.lines.extend(lines)


# Phase 8 -------------------------------------------------------------------------------------

def summary_lines(run: Run) -> list[str]:
    """Return the packages the run leaves in the old installations, and note what is left for the user to do

    An app that only the user can uninstall joins the run's hand tasks.

    @param run  the run
    @returns    the lines phase 8 prints before its checks
    """
    plan = run.plan
    lines = []
    for packages, why in ((plan.kept, ""), (plan.left_in_place, ", whose `%s` command cannot run")):
        held: dict[str, list[str]] = {}
        for pkg in packages:
            held.setdefault(pkg.instance_prefix, []).append(pkg.name)
        for prefix, names in sorted(held.items()):
            inst = run.instance(prefix)
            where = at(inst) if inst is not None else prefix
            reason = why % COMMAND_OF[inst.manager] if why and inst is not None else ""
            lines.append(f"{counted(len(names), 'package')} stay{'s' if len(names) == 1 else ''} in {where}{reason}: "
                         f"{some(names)}")
    packages = run.bundle.result.packages if run.bundle is not None else []
    sources = {run.fresh_prefix(prefix) for prefix in plan.source_prefixes}
    for token in plan.manual_casks:
        owner = next((p.instance_prefix for p in packages if p.kind == "cask" and p.name == token
                      and p.instance_prefix in sources), None)
        inst = run.instance(owner) if owner else None
        brew = inst.binary if inst is not None and inst.binary else "brew"
        task = (f"Uninstall the app {token} yourself, because Homebrew asks for your password: "
                f"{typed([brew, 'uninstall', '--cask', token])}")
        if task not in run.todo:
            run.todo.append(task)
    return lines


def uninstalled(run: Run) -> list[str]:
    """Return the prefixes of the old installations that phase 6 was to uninstall and that are gone

    @param run  the run, after its last scan
    @returns    the prefixes where the scan finds no installation
    """
    return [prefix for prefix in run.removed if run.fresh_instance(prefix) is None]


def newer(run: Run) -> tuple[list[str], str, bool] | None:
    """Return the packages of the target that still have a newer version, and the command that upgrades them

    A pinned package does not count: the command leaves it as it is. MacPorts builds in trace mode while a
    Homebrew is installed, as the run's own builds do.

    @param run  the run, after its last scan
    @returns    their names, the command as the user types it, and whether the target has a pinned package,
                whose dependencies the command upgrades too; None when none has a newer version, or when
                phase 8 took no inventory to count them in
    """
    target = run.target
    if target is None or run.bundle is None or 8 not in phase_numbers(run.plan):
        return None
    mine = [pkg for pkg in run.bundle.result.packages if pkg.instance_prefix == target.prefix]
    names = [pkg.name for pkg in mine if pkg.outdated and not pkg.pinned and (pkg.kind != "port" or pkg.active)]
    if not names:
        return None
    pins = any(pkg.pinned for pkg in mine)
    if target.manager is Manager.BREW:
        return names, brew_actions.typed_line(target, ["upgrade"], run.runner.host_arch), pins
    port = target.binary or os.path.join(target.prefix, "bin", "port")
    return names, typed([port, *(["-t"] if run.homebrew_present else []), "upgrade", "outdated"], True), pins


def verify_phase(run: Run) -> None:
    """Run phase 8: `verify` over a fresh inventory; exit 5 on a failure

    @param run    the run
    @throws Stop  exit 5 when a check fails
    """
    for line in summary_lines(run):
        run.say("  " + line)
    if run.dry_run:
        run.say("  Would check the result and write report.md to the run folder.")
        return
    bundle = run.fresh_scan()
    scan.write(bundle, run.run_dir)
    result = module("verify").check(bundle, run.plan, run.runner, run_dir=run.run_dir)
    keep_tasks(run, result.tasks)
    if result.ok:
        run.say("  Passed: the replacements are in place, and what the plan uninstalls is gone.")
    for failure in result.failures:
        run.say("  " + failure.line())
    for note in result.reports:
        run.say("  note " + note.line())
    if result.exit_code:
        raise Stop(EXIT_VERIFY, [
            f"the final check found {counted(len(result.failures), 'failure')}, listed above",
            "  Once they are settled, check again with: brew-ports verify "
            + shlex.quote(run.run_dir.sub(PLAN_FILE))])


PHASES: dict[int, Callable[[Run], None]] = {
    0: preflight, 1: snapshot_phase, 2: exec_install.repair, 3: exec_install.install, 4: gate,
    5: exec_remove.remove, 6: remove_managers, 7: exec_env.environment, 8: verify_phase,
}


def phase_numbers(plan: Plan) -> list[int]:
    """Return the plan's phase numbers in order, phase 0 always first

    @param plan  the plan
    @returns     the numbers of the plan's phases that `PHASES` runs
    """
    return [0] + sorted({p.number for p in plan.phases if p.number in PHASES and p.number != 0})


def run_phases(run: Run) -> None:
    """Run every phase of the plan in order, with a `<n>.complete` line after each

    `--stop-after N` ends the run once the next phase would be past N.

    @param run    the run
    @throws Stop  exit 0 when `--stop-after` ends the run; a phase's own stop passes through
    """
    numbers = phase_numbers(run.plan)
    run_id = run.run_dir.run_id
    for index, number in enumerate(numbers):
        run.header(number)
        PHASES[number](run)
        run.heading = None
        if not run.dry_run:
            run.complete(number)
        following = numbers[index + 1] if index + 1 < len(numbers) else None
        if run.stop_after is not None and following is not None and following > run.stop_after:
            raise Stop(EXIT_OK, apply_report.stopped_after(number, run.stop_after, run_id, run.dry_run), error=False)
    if run.dry_run:
        lines = apply_report.dry_finished(None if run.resumed else run.ctx.args.plan, run_id, run.todo)
    else:
        lines = apply_report.finished(run.plan, uninstalled(run), run_id, run.todo, newer(run))
    for line in lines:
        run.say(line)


# Starting and resuming -----------------------------------------------------------------------

def read_plan(path: str) -> tuple[Plan, str]:
    """Return a `plan.json` and its text; a `plan-refused.json`, with its top-level `refused` key, exits 3

    @param path   the plan file
    @returns      the plan and the file's text
    @throws Stop  exit 2 for a file that cannot be read or holds no plan, exit 3 for a refused plan
    """
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise Stop(EXIT_USAGE, [f"cannot read {tilde(path)}: {exc.strerror or exc}",
                                "  Give the file that `brew-ports plan` saved."]) from None
    try:
        data = json.loads(text)
    except ValueError:
        raise Stop(EXIT_USAGE, [f"{tilde(path)} is not a plan: it does not hold JSON", MAKE_NEW_PLAN]) from None
    if isinstance(data, dict) and "refused" in data:
        reasons = (data.get("refused") or {}).get("reasons") or []
        raise Stop(EXIT_PREFLIGHT, [f"{tilde(path)} is not a plan: it holds the reasons why no plan was made"]
                   + [f"    {r}" for r in reasons] + ["  Settle them, then " + NEW_PLAN + "."])
    try:
        plan = model.from_dict(Plan, data)
    except (TypeError, KeyError, ValueError, AttributeError):
        raise Stop(EXIT_USAGE, [f"{tilde(path)} is not a plan this version of brew-ports can read",
                                MAKE_NEW_PLAN]) from None
    return plan, text


def _marker_text(state_dir: state.StateDir) -> str:
    """Return the command that last changed this Mac, and its run, as a refusal names them

    @param state_dir  the state directory
    @returns          the command in backticks, then its run id in parentheses
    """
    marker = state_dir.dirty() or {}
    command = f"`brew-ports {marker['command']}`" if marker.get("command") else "another brew-ports command"
    return f"{command} (run {marker.get('run_id') or '?'})"


def new_run(ctx: Context, path: str, dry_run: bool) -> tuple[state.RunDir, Plan, str]:
    """Create the run of `apply PLAN`, and return it with the plan and the plan's path

    A refused plan, or one older than the dirty marker, exits 3 before a run exists; a dry run copies no
    plan into its run, so it can never be resumed.

    @param ctx      the command's context
    @param path     the PLAN argument
    @param dry_run  whether the run is `--dry-run`
    @returns        the run directory, the plan and the plan's absolute path
    @throws Stop    exit 2 for a file that holds no plan, exit 3 for a refused plan or one older than the marker
    """
    path = os.path.abspath(os.path.expanduser(path))
    plan, text = read_plan(path)
    if ctx.state.older_than_dirty(path):
        raise Stop(EXIT_PREFLIGHT, [f"{tilde(path)} was made before {_marker_text(ctx.state)} changed this Mac, so it "
                                    "may be out of date", MAKE_NEW_PLAN])
    run_dir = ctx.state.new_run()
    if not dry_run:
        run_dir.write_json(PLAN_FILE, text)
        run_dir.journal.append({"ts": state.now_iso(), "phase": 0, "action_id": START, "kind": "note",
                                "plan": path})
    return run_dir, plan, path


def resumed_run(ctx: Context, run_id: str) -> tuple[state.RunDir, Plan, str]:
    """Return the run of `apply --resume RUN-ID` with its own plan and the plan's path

    Another command's touch of the marker after the run started refuses the resume; the run's own touches
    do not.

    @param ctx     the command's context
    @param run_id  the RUN-ID argument
    @returns       the run directory, its plan and the plan's path
    @throws Stop   exit 2 for an unknown run or one that `apply PLAN` did not start, exit 3 when another
                   command changed the host after the run started
    """
    try:
        run_dir = ctx.state.run(run_id)
    except (ValueError, FileNotFoundError):
        raise Stop(EXIT_USAGE, [f"there is no run {run_id}",
                                f"  Each run has a folder of its name in {tilde(ctx.state.runs)}."]) from None
    path = run_dir.sub(PLAN_FILE)
    if not os.path.isfile(path) or not any(e.get("action_id") == START for e in run_dir.journal.entries()):
        raise Stop(EXIT_USAGE, [f"run {run_id} is a dry run, or no run of `brew-ports apply`: there is nothing to "
                                "continue",
                                "  Start one with: brew-ports apply PLAN"])
    plan, _ = read_plan(path)
    if ctx.state.marker_blocks_resume(run_dir.run_id, os.stat(path).st_mtime_ns):
        raise Stop(EXIT_PREFLIGHT, [f"{_marker_text(ctx.state)} changed this Mac after run {run_id} started, so the "
                                    "run's plan may be out of date", MAKE_NEW_PLAN])
    return run_dir, plan, path


def failure_lines(exc: Exception) -> list[str]:
    """Return the error of a command or a check that stopped the run

    @param exc  the runner's error, or phase 6's stop, which carries its own reason
    @returns    the statement, and where a failed command's output is kept
    """
    reason = getattr(exc, "reason", None)
    if reason:
        return [str(reason)]
    result = getattr(exc, "result", None)
    if isinstance(exc, ActionFailed) and result is not None:
        return [apply_report.failed(result), "  Its whole output is in the folder `out` of the run folder."]
    return [str(exc)]


def finish(run: Run, stop: Stop) -> int:
    """Print why the run stopped and return its exit code

    A stop the user asked for prints as it is. Any other is an error under its phase's heading: each statement
    under the tool's name, its indented lines below it, and last the command that continues the run when one does.
    The hand tasks gathered so far follow, so a run that stops early does not lose them; a failed final check
    is followed by the undo command and the report as well.

    @param run   the run
    @param stop  why it stopped
    @returns     the stop's exit code
    """
    lines = list(stop.lines)
    run_id = run.run_dir.run_id
    resume = apply_report.resume(run_id)
    if stop.error and stop.code == EXIT_ACTION and not run.dry_run and not any(resume in line for line in lines):
        lines.append(f"  Continue with: {resume}")
    if stop.error:
        run.flush()
    for line in lines:
        if not stop.error:
            run.say(line)
        elif line.startswith(" "):
            run.warn(line)
        else:
            run.error(line)
    if stop.code == EXIT_VERIFY:
        left = apply_report.leftovers(run.plan, uninstalled(run), run_id, run.todo)
    else:
        left = apply_report.tasks(run.todo, run.dry_run)
    for line in left:
        run.say(line)
    run.journal({"action_id": f"{run.runner.phase}.stopped", "kind": "note", "exit": stop.code,
                 "lines": stop.lines})
    return stop.code


def opening_lines(run: Run) -> list[str]:
    """Return the first lines of a start: what moves where, or where a resumed run continues

    @param run  the run
    @returns    the lines; a dry run says first that nothing will change
    """
    folder = run.run_dir.path
    if not run.resumed:
        return apply_report.opening(run.plan, run.removed, folder, run.dry_run)
    done = max((n for n in phase_numbers(run.plan) if n and run.completed(n)), default=None)
    return (["Dry run: nothing will change."] if run.dry_run else []) + apply_report.continuing(
        run.run_dir.run_id, done, folder)


def cmd_apply(ctx: Context, make_runner: Callable[[Context, state.RunDir], BaseRunner] | None = None) -> int:
    """Run `brew-ports apply PLAN | --resume RUN-ID [--yes] [--dry-run] [--stop-after N]`

    Exit 3 refuses the run, 4 stops it with the resume command, 5 means phase 8 found a failure.

    @param ctx          the command's context
    @param make_runner  the runner factory, given the context and the run directory; None for `command_runner`
    @returns            the exit code
    """
    args = ctx.args
    dry_run = args.dry_run
    resume = args.resume
    try:
        run_dir, plan, path = resumed_run(ctx, resume) if resume else new_run(ctx, args.plan, dry_run)
    except Stop as stop:
        for line in stop.lines:
            (ctx.console.warn if line.startswith(" ") else ctx.console.error)(line)
        return stop.code
    runner = (make_runner or command_runner)(ctx, run_dir)
    ctx.runner = runner
    ctx.console.echo = False
    runner.phase = 0
    run = Run(ctx, runner, run_dir, plan, path, resumed=bool(resume), dry_run=dry_run, stop_after=args.stop_after)
    for line in opening_lines(run):
        run.say(line)
    code = EXIT_OK
    with runner.signals():
        try:
            run_phases(run)
        except Stop as stop:
            code = finish(run, stop)
        except PreflightError as exc:
            code = finish(run, Stop(EXIT_PREFLIGHT, [str(exc)]))
        except (ActionFailed, EscalationFailed) as exc:
            code = finish(run, Stop(EXIT_ACTION, failure_lines(exc)))
        except Interrupted:
            code = finish(run, Stop(EXIT_ACTION, ["interrupted; a command that was running got the interrupt too, and "
                                                  "the run waited for it to end"]))
        finally:
            run.close()
            if not (dry_run and resume):          # a dry run of a resume keeps the run's own report
                run.write_report()
    return code

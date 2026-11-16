"""`brew-ports apply`: a new or resumed run takes a plan through phases 0 to 8

Phases 2 and 3 live in `exec_install`, phase 5 in `exec_remove`, phase 7 in `exec_env`, the others here.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable

from . import doctor, exec_env, exec_install, exec_remove, model, scan, snapshot, state, system
from .context import Context
from .exec_run import (EXIT_ACTION, EXIT_OK, EXIT_PREFLIGHT, EXIT_USAGE, EXIT_VERIFY, PLAN_FILE, SOURCE_BIN, START,
                       Run, Stop, module, phase6_prefixes)
from .model import Instance, Manager, Plan, is_recorded_as
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
        remove_prefixes=tuple(run.fresh_prefix(p) for p in phase6_prefixes(plan)),
        exempt_prefixes=tuple(run.fresh_prefix(p) for p in exempt))


def blocking_lines(run: Run) -> list[str]:
    """Return the findings that block this plan (exit 3), each with its remedies

    Low disk space does not count in a resumed run past phase 3, whose own installs used the space.

    @param run  the run, with the findings of its phase 0 scan
    @returns    the lines to print; empty when nothing blocks
    """
    found = doctor.blocking(run.issues, plan_context(run))
    if run.resumed and run.past(3):
        found = [i for i in found if i.code != "system-low-disk-space"]
    lines = doctor.blocked_by_lines(found)
    if any((i.auto_fix or i.confirm_each) and any(not a.manual for a in i.remedies) for i in found):
        lines.append("`brew-ports doctor --fix` applies the remedies the tool runs")
    return lines


def _repairs(run: Run, inst: Instance) -> str:
    """Return how to repair an instance that cannot be driven: the findings `doctor --fix` repairs, else `doctor`

    @param run   the run, with the findings of its phase 0 scan
    @param inst  the instance
    @returns     the advice that ends the instance's line
    """
    codes = sorted({i.code for i in run.issues if i.instance_prefix == inst.prefix
                    and (i.auto_fix or i.confirm_each) and i.remedies})
    if codes:
        return f"`brew-ports doctor --fix` repairs it ({', '.join(codes)})"
    return "`brew-ports doctor` names the repair"


def drivability_lines(run: Run) -> list[str]:
    """Return why the target, or a source the plan uninstalls from through its binary, cannot be driven

    A source whose phase 6 deletion has begun is exempt.

    @param run  the run, after its phase 0 scan
    @returns    one line per instance that is gone or cannot be driven
    """
    plan = run.plan
    wanted = [(plan.target_prefix, "the target")]
    for prefix, pairs in sorted(plan.removal_set.items()):
        if any(kind != "cask-adopted" for kind, _ in pairs) and not run.phase6_begun(prefix):
            wanted.append((prefix, "the source"))
    lines = []
    for prefix, role in wanted:
        inst = run.fresh_instance(prefix)
        if inst is None:
            lines.append(f"{role} {prefix} is not found on this host any more: re-plan")
        elif not inst.drivable:
            detail = f": {inst.usability_detail}" if inst.usability_detail else ""
            lines.append(f"{role} {prefix} cannot be driven ({inst.usability.value}{detail}): {_repairs(run, inst)}")
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
        run.say(f"  no Homebrew catalogue for {target.prefix}, so refused() is not asked")
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
                hint = f", suggestion: --map {m.source.name}={swap}" if swap else ""
                lines.append(f"Homebrew refuses to install {kind} {name}: disabled since {why.get('date')} "
                             f"({why.get('because')}){hint}; re-plan")
    return lines


def needs_sudo(run: Run) -> bool:
    """Return whether anything of the plan escalates, so phase 0 runs `sudo -v`

    A source's line in `/etc/paths` counts, because phase 7 may rewrite that file.

    @param run  the run, after its phase 0 scan
    @returns    True when a phase of the run calls sudo
    """
    plan = run.plan
    if any(a.sudo for n in (2, 3) for a in run.actions(n)) or phase6_prefixes(plan):
        return True
    starts = plan.options.get("start_services") == "true"
    if plan.target is Manager.PORTS and (plan.target_upgrades or starts or any(m.selections for m in plan.mappings)):
        return True
    for prefix, pairs in plan.removal_set.items():
        inst = run.instance(prefix)
        if pairs and inst is not None and inst.manager is Manager.PORTS:
            return True
    if any(s.scope == "system" or s.domain == "system" for s in exec_remove.selected_services(run)):
        return True
    if not snapshot.is_complete(run.run_dir) and any(
            inst.manager is Manager.PORTS and inst.drivable and "snapshot" in inst.features
            for inst in snapshot_instances(run)):
        return True
    if exec_remove.shell_switch(run) is not None:
        return True
    sources = {run.fresh_prefix(p) for p in plan.source_prefixes}
    for line in run.bundle.result.environment.get("etc_paths") or []:
        entry = (line or {}).get("entry") or {}
        if not line.get("stock") and entry.get("instance_prefix") in sources:
            return True
    return False


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
    run.say(f"  scan: {len(bundle.result.instances)} instance(s), {len(bundle.result.packages)} package(s)")
    run.issues = doctor.detect_all(bundle, run.runner)
    lines = blocking_lines(run) + drivability_lines(run) + refused_lines(run)
    if lines:
        if run.resumed and any("doctor --fix" in line for line in lines):
            lines.append("a `brew-ports doctor --fix` repair changes the host, which makes this run's plan stale: "
                         "plan again after it")
        raise Stop(EXIT_PREFLIGHT, lines)
    run.say("  blocking findings: none")
    record_source_bin(run)
    if run.dry_run:
        return
    if needs_sudo(run):
        run.runner.sudo_preflight()
        run.runner.keepalive(force=True)
        if run.runner.keepalive_failed:
            raise Stop(EXIT_PREFLIGHT, ["the first sudo keepalive failed: sudo caches no credentials"])
        run.say("  sudo: credentials cached")


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

    Its files record the host before the run, so a resume never takes them again.

    @param run  the run
    """
    if snapshot.is_complete(run.run_dir):
        run.say("  the snapshot of this run is complete: not taken again")
        return
    instances = snapshot_instances(run)
    run.say(f"  snapshot of {', '.join((i.prefix for i in instances))} into {snapshot.snapshot_dir(run.run_dir)}")
    if run.dry_run:
        return
    run.confirm(1)
    written = snapshot.write(run.runner, run.run_dir, run.bundle, instances, rc_files=rc_files(run.bundle),
                             id_prefix="1", uid=run.uid)
    if snapshot.NOTES in written:
        run.say(f"  steps that failed are listed in {written[snapshot.NOTES]}")


# Phase 4 -------------------------------------------------------------------------------------

def recovery_lines(run: Run, result) -> list[str]:
    """Return what the user can do after a failed gate

    @param run     the run
    @param result  the gate's result
    @returns       the resume, re-plan and rollback commands
    """
    roots: list[str] = []
    for m in run.plan.mappings:
        subjects = {f"{m.source.name} -> {m.target_name}", m.source.name, m.target_name or ""} | set(m.companions)
        if any(f.subject in subjects for f in result.failures) and m.source.name not in roots:
            roots.append(m.source.name)
    run_id = run.run_dir.run_id
    keep = ",".join(roots) or "<root>"
    return [f"fix the cause, then `brew-ports apply --resume {run_id}`",
            f"or plan again with the failed roots kept: `brew-ports plan --target {run.plan.target.value} --keep "
            f"{keep}` (or an --only without them)",
            f"or `brew-ports rollback {run_id}` reinstalls a target package a repair dropped"]


def gate(run: Run) -> None:
    """Run phase 4, `verify.check(gate=True)` over a fresh inventory

    A failure stops the run with exit 4 before any source package is removed; no flag lets a root through
    without its replacement.

    @param run    the run
    @throws Stop  exit 4 when the gate fails
    """
    if run.dry_run:
        run.say("  replacements installed, commands provided and clean linkage over every root, companion and "
                "the target, the packages active before the run still active, target_upgrades installed")
        return
    bundle = run.fresh_scan()
    result = module("verify").check(bundle, run.plan, run.runner, gate=True, run_dir=run.run_dir)
    for line in result.lines():
        run.say("  " + line)
    if not result.ok:
        run.journal({"action_id": "4.gate", "kind": "note", "failures": [f.line() for f in result.failures]})
        raise Stop(EXIT_ACTION, ["the gate failed: no source package was removed"] + recovery_lines(run, result))


# Phase 6 -------------------------------------------------------------------------------------

def remove_managers(run: Run) -> None:
    """Run phase 6 for every instance `--remove-manager` names

    `remove_manager` recomputes its lists and checks, and asks its own confirmations through `ctx`.

    @param run                      the run
    @throws remove_manager.Stopped  a check, an archive or a deletion stopped phase 6; its lines join the report
    """
    named = [p for p in run.plan.options.get("remove_manager", "").split(",") if p]
    if not named:
        run.say("  no source manager is removed")
        return
    phase = run.phase(6)
    for action in phase.actions if phase else []:
        run.say(f"  {action.action_id}: {doctor.describe(action)}")
    if run.dry_run:
        run.say("  (previews from the plan: phase 6 recomputes them from the live inventory)")
        return
    run.confirm(6, f" for {', '.join(named)}")
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

def summary_lines(plan: Plan) -> list[str]:
    """Return what the run leaves to the user: kept and left packages, manual casks, upgrades in place

    @param plan  the plan
    @returns     the lines phase 8 prints before its checks
    """
    lines = []
    kept: dict[str, list[str]] = {}
    for pkg in plan.kept:
        kept.setdefault(pkg.instance_prefix, []).append(pkg.name)
    for prefix, names in sorted(kept.items()):
        lines.append(f"still provided by {prefix}: {', '.join(names)}")
    left: dict[str, list[str]] = {}
    for pkg in plan.left_in_place:
        left.setdefault(pkg.instance_prefix, []).append(pkg.name)
    for prefix, names in sorted(left.items()):
        lines.append(f"left in place in {prefix}, which cannot be driven: {', '.join(names)}")
    for token in plan.manual_casks:
        lines.append("to run on a terminal after the migration (Homebrew calls sudo for it): `brew uninstall --cask "
                     f"{token}`")
    if plan.target_upgrades:
        lines.append(f"upgraded in place in {plan.target_prefix}: {', '.join(plan.target_upgrades)}")
    return lines


def verify_phase(run: Run) -> None:
    """Run phase 8: `verify` over a fresh inventory; exit 5 on a failure

    @param run    the run
    @throws Stop  exit 5 when a check fails
    """
    for line in summary_lines(run.plan):
        run.say("  " + line)
    if run.dry_run:
        run.say("  verify over a fresh inventory, then report.md")
        return
    bundle = run.fresh_scan()
    scan.write(bundle, run.run_dir)
    result = module("verify").check(bundle, run.plan, run.runner, run_dir=run.run_dir)
    for line in result.lines():
        run.say("  " + line)
    if result.exit_code:
        raise Stop(EXIT_VERIFY, [f"verify found {len(result.failures)} failure(s): `brew-ports verify "
                                 f"{run.run_dir.sub(PLAN_FILE)}` checks again"])


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
    for index, number in enumerate(numbers):
        run.header(number)
        PHASES[number](run)
        if not run.dry_run:
            run.complete(number)
        following = numbers[index + 1] if index + 1 < len(numbers) else None
        if run.stop_after is not None and following is not None and following > run.stop_after:
            dry = " --dry-run" if run.dry_run else ""
            raise Stop(EXIT_OK, [f"apply{dry} stopped after phase {number} (--stop-after {run.stop_after})"])
    run.say("")
    if run.dry_run:
        run.say("apply --dry-run: nothing was changed and no marker was touched")
    else:
        run.say(f"apply: run {run.run_dir.run_id} finished")


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
        raise Stop(EXIT_USAGE, [f"cannot read {path}: {exc.strerror or exc}"]) from None
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise Stop(EXIT_USAGE, [f"{path} is not JSON: {exc}"]) from None
    if isinstance(data, dict) and "refused" in data:
        reasons = (data.get("refused") or {}).get("reasons") or []
        raise Stop(EXIT_PREFLIGHT, [f"{path} is a refused plan (plan-refused.json): re-plan"]
                   + [f"  {r}" for r in reasons])
    try:
        plan = model.from_dict(Plan, data)
    except (TypeError, KeyError, ValueError, AttributeError) as exc:
        raise Stop(EXIT_USAGE, [f"{path} is not a plan: {exc}"]) from None
    return plan, text


def _marker_text(state_dir: state.StateDir) -> str:
    """Return the command that last touched the dirty marker, and its run, as a refusal names them

    @param state_dir  the state directory
    @returns          the command in backticks, then its run id in parentheses
    """
    marker = state_dir.dirty() or {}
    return f"`{marker.get('command') or 'a mutating command'}` (run {marker.get('run_id') or '?'})"


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
        raise Stop(EXIT_PREFLIGHT, [f"{path} is older than the last change to this host by "
                                    f"{_marker_text(ctx.state)}: re-plan"])
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
        raise Stop(EXIT_USAGE, [f"no run {run_id} in {ctx.state.runs}"]) from None
    path = run_dir.sub(PLAN_FILE)
    if not os.path.isfile(path) or not any(e.get("action_id") == START for e in run_dir.journal.entries()):
        raise Stop(EXIT_USAGE, [f"run {run_id} is not an apply run: `brew-ports apply PLAN` starts one"])
    plan, _ = read_plan(path)
    if ctx.state.marker_blocks_resume(run_dir.run_id, os.stat(path).st_mtime_ns):
        marker = _marker_text(ctx.state)
        raise Stop(EXIT_PREFLIGHT, [f"{marker} changed this host after run {run_id} started, so its plan no longer "
                                    "describes the host: re-plan"])
    return run_dir, plan, path


def finish(run: Run, stop: Stop) -> int:
    """Print why the run stopped and return its exit code; exit 4 and `--stop-after` name the resume command

    @param run   the run
    @param stop  why it stopped
    @returns     the stop's exit code
    """
    for line in stop.lines:
        (run.say if stop.code == EXIT_OK else run.warn)(line)
    if stop.code in (EXIT_OK, EXIT_ACTION) and not run.dry_run:
        run.warn(f"`brew-ports apply --resume {run.run_dir.run_id}` continues the run")
    run.journal({"action_id": f"{run.runner.phase}.stopped", "kind": "note", "exit": stop.code,
                 "lines": stop.lines})
    return stop.code


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
            ctx.console.warn(f"brew-ports apply: {line}")
        return stop.code
    runner = (make_runner or command_runner)(ctx, run_dir)
    ctx.runner = runner
    runner.phase = 0
    run = Run(ctx, runner, run_dir, plan, path, resumed=bool(resume), dry_run=dry_run, stop_after=args.stop_after)
    run.say(f"apply {path}: run {run_dir.run_id}{' (resumed)' if resume else ''}")
    code = EXIT_OK
    with runner.signals():
        try:
            run_phases(run)
        except Stop as stop:
            code = finish(run, stop)
        except PreflightError as exc:
            code = finish(run, Stop(EXIT_PREFLIGHT, [str(exc)]))
        except (ActionFailed, EscalationFailed) as exc:
            code = finish(run, Stop(EXIT_ACTION, [f"phase {runner.phase} stopped: {exc}"]))
        except Interrupted:
            code = finish(run, Stop(EXIT_ACTION, [f"phase {runner.phase} was interrupted; the command that was "
                                                  "running was waited for"]))
        finally:
            run.close()
            if not (dry_run and resume):          # a dry run of a resume keeps the run's own report
                run.write_report()
    return code

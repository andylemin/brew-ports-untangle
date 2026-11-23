"""Phase 7 of `apply`: the environment cleanup, `port select --set`, the notes and `--start-services`

Every start recomputes the phase from the live host, so its journal entries are records, never skip rules.
"""

from __future__ import annotations

import dataclasses
import os

from . import apply_report, snapshot
from .exec_run import EXIT_ACTION, Stop, module
from .homebrew import actions as brew_actions
from .homebrew.catalogue import Catalogue
from .macports import actions as mp_actions
from .model import Action, Manager, Mapping, OnFailure, Service
from .plan_sets import name_key
from .report import at, counted, series, some, tilde

LANGUAGE_KINDS = ("pip", "npm", "gem", "cpan")


def _read_lines(path: str) -> list[str] | None:
    """Return the lines of a text file

    @param path  the file
    @returns     the lines, or None when the file cannot be read
    """
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().splitlines()
    except OSError:
        return None


def select_commands(prefix: str, group: str, option: str) -> list[str] | None:
    """Return the commands a selection links, or None when the group's `base` or option file is missing

    They are the `bin/` entries of `base` whose line in the option's file is not `-`.

    @param prefix  the MacPorts target's prefix
    @param group   the select group, such as `python3`
    @param option  the option the selection sets, such as `python313`
    @returns       the command names, or None
    """
    base = _read_lines(os.path.join(prefix, "etc", "select", group, "base"))
    chosen = _read_lines(os.path.join(prefix, "etc", "select", group, option))
    if base is None or chosen is None:
        return None
    return [os.path.basename(b.strip()) for b, o in zip(base, chosen)
            if b.strip().startswith("bin/") and o.strip() != "-"]


def selections(run) -> tuple[list[Action], list[str]]:
    """Return the `port select --set` actions of a MacPorts target, and report lines for the rest

    A selection is set only when each of its commands existed as `<source prefix>/bin/<command>` at the first start.

    @param run  the run
    @returns    the actions, and one line per selection that is not set
    """
    target = run.target
    if target is None or run.plan.target is not Manager.PORTS:
        return [], []
    recorded = run.read_source_bin()
    actions: list[Action] = []
    reported: list[str] = []
    seen = set()
    for m in run.plan.mappings:
        for group, option in m.selections:
            if group in seen:
                continue
            seen.add(group)
            action = dataclasses.replace(mp_actions.select_set(target, run.runner.host_arch, f"7.select.{group}",
                                                               group, option), on_failure=OnFailure.PROBE)
            if run.dry_run:                 # only the run knows what the replacement offers and what was recorded
                actions.append(action)
                continue
            commands = select_commands(target.prefix, group, option)
            source = recorded.get(m.source.instance_prefix)
            if commands is None:
                reported.append(f"{option} is not made the default `{group}`: MacPorts at {target.prefix} offers no "
                                "such choice.")
                continue
            if source is None:
                why = f"the commands {m.source.instance_prefix} provided were not recorded before the uninstall"
            else:
                missing = [c for c in commands if c not in source]
                why = f"{m.source.instance_prefix} did not provide {series(missing)} either" if missing else ""
            if why:
                reported.append(f"{option} is not made the default `{group}`, because {why}. To do it yourself: sudo "
                                f"port select --set {group} {option}")
                continue
            actions.append(action)
    return actions, reported


def interpreter_notes(run) -> list[str]:
    """Return the notes of phase 7: versioned interpreters on a Homebrew target, unmigrated language packages

    A versioned interpreter's unversioned names belong to the formula the catalogue aliases them to.

    @param run  the run
    @returns    the note lines
    """
    out = []
    target = run.target
    catalogue = run.bundle.catalogue(target.prefix) if target is not None and run.bundle is not None else None
    if target is not None and run.plan.target is Manager.BREW:
        for name in dict.fromkeys(m.target_name or "" for m in run.plan.mappings if m.target_kind == "formula"):
            if "@" not in name:
                continue
            base, version = name.split("@", 1)
            owner = catalogue.canonical(base) if catalogue is not None else None
            if owner == name:
                continue
            versioned = [e for e in (catalogue.executables(name) if catalogue is not None else []) if version in e]
            commands = f"{series(versioned)}, or the commands in " if versioned else "the commands in "
            out.append(f"{name} does not provide plain `{base}`: that name belongs to {owner or 'another formula'}. "
                       f"Use {commands}{target.prefix}/opt/{name}/bin.")
    names = [m.source.name for m in run.plan.unmigratable if m.target_kind in LANGUAGE_KINDS]
    if names:
        out.append(f"{counted(len(names), 'language package')} did not move, as the plan said: {some(names)}")
    return out


def _mapping_of(run, service: Service) -> Mapping | None:
    """Return the plan's mapping of the source package that owns a service

    @param run      the run
    @param service  a recorded source service
    @returns        the mapping, or None when the plan maps no such package
    """
    for m in run.plan.mappings:
        src = m.source
        if run.fresh_prefix(src.instance_prefix) == run.fresh_prefix(service.instance_prefix) \
                and src.kind == service.package_kind \
                and name_key(src.kind, src.name) == name_key(src.kind, service.package or ""):
            return m
    return None


def recorded_services(run) -> list[Service]:
    """Return the loaded source services of removed packages, as the phase 1 snapshot recorded them

    These are what `--start-services` replaces.

    @param run  the run
    @returns    the services, source by source
    """
    plan = run.plan
    pairs = {(run.fresh_prefix(p), k, name_key(k, n)) for p, ps in list(plan.removal_set.items())
             + list(plan.path_removed.items()) for k, n in ps if k != "cask-adopted"}
    out = []
    for prefix in plan.source_prefixes:
        inst = run.instance(prefix)
        if inst is None:
            continue
        sub = snapshot.brew_dir(run.run_dir, inst.prefix) if inst.manager is Manager.BREW \
            else snapshot.ports_dir(run.run_dir, inst.prefix)
        path = os.path.join(sub, snapshot.SERVICES)
        try:
            services = snapshot.read_services(path)
        except (OSError, ValueError):
            continue
        for svc in services:
            kind = svc.package_kind or ""
            key = (run.fresh_prefix(svc.instance_prefix), kind, name_key(kind, svc.package or ""))
            if svc.owned and svc.loaded and key in pairs:
                out.append(svc)
    return out


def _brew_label(run, target, formula: str) -> str:
    """Return the launchd label Homebrew 7 loads a formula's service under

    That is the `:macos` value of its `service_name_args`, else `sh.brew.<formula>`.

    @param run      the run, for its environment and host architecture
    @param target   the Homebrew target, whose catalogue is read
    @param formula  the replacement formula
    @returns        the label
    """
    catalogue = Catalogue.load(target, run.environ, run.runner.host_arch)
    if catalogue is not None:
        for label, name in catalogue.service_labels().items():
            if name == formula and not label.startswith(("sh.brew.", "homebrew.mxcl.")):
                return label
    return f"sh.brew.{formula}"


def starts(run) -> tuple[list[Action], list[str]]:
    """Return the `--start-services` starts of the recorded source services' replacements, and manual lines

    A system-scope service on a Homebrew target is a manual line, because starting it runs `brew` as root.

    @param run  the run
    @returns    the starts, each once, and a line per service to start by hand
    """
    target = run.target
    if target is None or run.plan.options.get("start_services") != "true":
        return [], []
    host = run.runner.host_arch
    actions: dict[str, Action] = {}
    manual: list[str] = []
    for svc in recorded_services(run):
        m = _mapping_of(run, svc)
        if m is None or m.target_kind not in ("formula", "port") or not m.target_name:
            manual.append(f"The service {svc.label} is not started: no replacement in {at(target)} provides it.")
            continue
        if target.manager is Manager.BREW:
            if svc.scope == "system":
                task = (f"Start the system service of {m.target_name} yourself, because that runs Homebrew as root: "
                        f"sudo brew services start {m.target_name}")
                if task not in manual:
                    manual.append(task)
                continue
            label = _brew_label(run, target, m.target_name)
            action = brew_actions.services_start(target, host, f"7.start.{label}", m.target_name,
                                                 on_failure=OnFailure.PROBE)
        else:
            label = f"org.macports.{m.target_name}"
            action = dataclasses.replace(mp_actions.load(target, host, f"7.start.{label}", m.target_name),
                                         on_failure=OnFailure.PROBE)
        actions.setdefault(action.action_id, action)
    return list(actions.values()), manual


def environment(run) -> None:
    """Run phase 7: the environment cleanup, the selections, the notes and the service starts

    The cleanup weighs a scan taken after phase 6, because an undrivable source's packages go only with its deletion.

    @param run    the run
    @throws Stop  exit 4 when a file is not written or a selection or start fails
    """
    envclean = module("envclean")
    selected, reported = selections(run)
    started, manual = starts(run)
    notes = interpreter_notes(run)
    if run.dry_run:
        run.say("  Not shown in a dry run: what changes in your shell files depends on what phases 5 and 6 leave.")
        run.say("  The run shows each change before it makes any, and asks unless --yes is given.")
        for action in selected + started:
            run.show(action)
        if selected:
            run.say("  A default is set only where the old installation provided the same commands.")
        for line in notes:
            run.say("  " + line)
        run.todo += [task for task in manual if task not in run.todo]
        return
    bundle = run.fresh_scan()
    surv = envclean.survivors(bundle, run.plan, run.run_dir.journal)
    edits = envclean.compute(bundle, surv, run.home, run.environ)
    shown = [line for edit in edits for line in envclean.render(edit)]
    if shown:
        for line in envclean.survivor_lines(surv) + shown:
            run.say("  " + line)
    for action in selected + started:
        run.show(action)
    for line in notes:
        run.say("  " + line)
    run.todo += [task for task in reported + manual if task not in run.todo]
    run.todo += [f"Make the change phase 7 showed for {tilde(e.path, run.home)}, which brew-ports does not edit."
                 for e in edits if e.changed and e.manual]
    writable = [e for e in edits if e.changed and not e.manual]
    if not (writable or selected or started):
        return
    run.confirm(7)
    failures: list[str] = []
    if writable:
        if any(e.kind == "etc" for e in writable) and not run.runner.sudo_ready:
            run.runner.sudo_preflight()
        run.touch()
        result = envclean.apply(run.runner, run.run_dir, edits, run.root_files(), show=False)
        created = {e.realpath or os.path.realpath(e.path) for e in edits if e.old_text is None}
        for path in result.written:
            if path in created:
                run.say(f"  Created {tilde(path, run.home)}.")
            else:
                run.say(f"  Edited {tilde(path, run.home)}; the file as it was is kept in the run folder.")
        for path in result.removed:
            run.say(f"  Deleted {tilde(path, run.home)}.")
        for path in result.rejected:
            run.say(f"  Not edited: {tilde(path, run.home)}. The shell could not read the new version.")
            run.todo.append(f"Make the change phase 7 showed for {tilde(path, run.home)} yourself.")
        failures += [f"{tilde(path, run.home)} could not be written" for path in result.failed]
    for action in selected + started:
        outcome = run.runner.run(action)
        run.result_line(action, outcome)
        if not outcome.ok:
            failures.append(apply_report.failed(outcome))
    if failures:
        raise Stop(EXIT_ACTION, ["phase 7 did not finish"] + [f"    {f}" for f in failures])

"""Phases 2 and 3 of `apply`: the repairs of the target manager, the installs and the rebuilds

Homebrew counts a keg that a killed pour left as installed, so an unfinished install resumes as a reinstall.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from typing import Any

from . import doctor, env
from .env import linkage as env_linkage
from .homebrew import actions as brew_actions, inventory as brew_inventory
from .macports import actions as mp_actions, registry
from .model import Action, Instance, Issue, Manager, OnFailure, Severity
from .runner import ActionFailed

BREW_BATCHES = ("3.upgrade.formulae", "3.install.bottled", "3.install.built", "3.install.casks")
REGISTRY_ERRORS = (registry.RegistryMissing, registry.RegistryBusy, sqlite3.DatabaseError, OSError)


# Phase 2 -------------------------------------------------------------------------------------

def findings(actions: Sequence[Action]) -> list[list[Action]]:
    """Return the phase 2 actions grouped by finding

    The ids of a finding's actions differ only in their last step: `2.<code>.<subject>.<step>`.

    @param actions  the phase 2 commands
    @returns        one group per finding, in plan order
    """
    groups: dict[str, list[Action]] = {}
    for action in actions:
        groups.setdefault(action.action_id.rsplit(".", 1)[0], []).append(action)
    return list(groups.values())


def finding(group: Sequence[Action]) -> Issue:
    """Return the finding a group of phase 2 actions repairs, rebuilt for its post-check

    The code comes from the ids (`2.<code>...`), the subject from the `"<code> <subject>: "` description.

    @param group  the actions of one finding
    @returns      the finding, with the group as its remedies
    """
    first = group[0]
    parts = first.action_id.split(".")
    code = parts[1] if len(parts) > 2 else ""
    head = code + " "
    subject = first.description[len(head):].split(": ", 1)[0] if code and first.description.startswith(head) else ""
    return Issue(code=code, severity=Severity.HIGH, title=code, subject=subject or None,
                 instance_prefix=first.instance_prefix, evidence=[], remedies=list(group), auto_fix=False,
                 confirm_each=True, repairs_install=True, blocks=())


def repair_one(run, group: Sequence[Action]) -> None:
    """Run one finding's remedies; its post-check decides every result line, else the exit statuses do

    A failed repair leaves the decision to the phase 4 gate.

    @param run    the run
    @param group  the finding's actions; those `ok` in an earlier attempt are skipped
    """
    issue = finding(group)
    ran = []
    failure: str | None = None
    for action in group:
        if run.ok(2, action.action_id):
            continue
        try:
            ran.append((action, run.runner.run(action, defer_result=True)))
        except ActionFailed as exc:
            failure = str(exc)
            break
    if failure is None:
        checked = doctor.verify(issue, run.runner, run.bundle)
        if checked is False:
            failure = f"the post-check of {issue.code} found it unrepaired"
        elif checked is None and not all(result.ok for _, result in ran):
            failure = f"a command of {issue.code} failed"
    for action, _ in ran:
        if not action.read_only:
            run.runner.record_result(action, failure is None)
    label = f"{issue.code} {issue.subject or issue.instance_prefix or ''}"
    outcome = "repaired" if failure is None else f"not repaired ({failure}); the gate decides"
    run.say(f"  {label}: {outcome}")


def repair(run) -> None:
    """Run phase 2: the plan's repairs of the target, after one confirmation; no source package is touched

    @param run  the run
    """
    groups = findings(run.actions(2))
    pending = []
    for group in groups:
        for action in group:
            run.show(action, skipped=run.ok(2, action.action_id))
        if not all(run.ok(2, a.action_id) for a in group):
            pending.append(group)
    if not pending:
        run.say("  nothing to repair" if not groups else "  every repair passed in an earlier attempt")
        return
    if run.dry_run:
        return
    run.confirm(2)
    for group in pending:
        repair_one(run, group)


# The Cellar listing and the reinstall of an interrupted install --------------------------------

def read_listing(prefix: str) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Return the Cellar racks and Caskroom tokens of a prefix with their versions, skipping symlinks

    @param prefix  a Homebrew prefix
    @returns       the keg versions by rack, and the versions by cask token
    """
    racks, _ = brew_inventory.walk_cellar(prefix)
    rooms, _ = brew_inventory.walk_caskroom(prefix)
    return ({name: [k.version for k in rack.kegs] for name, rack in racks.items()},
            {token: list(room.versions) for token, room in rooms.items()})


def journal_listing(run, target: Instance, action: Action) -> None:
    """Journal the Cellar listing just before a Homebrew install, for a resume

    @param run     the run
    @param target  the Homebrew target
    @param action  the install about to run
    """
    cellar, caskroom = read_listing(target.prefix)
    run.journal({"action_id": action.action_id + ".listing", "kind": "listing", "of": action.action_id,
                 "cellar": cellar, "caskroom": caskroom})


def batch_names(action: Action) -> list[str]:
    """Return the names a batch install names: its `split_order`, else its argv's words past `split_head`

    @param action  a Homebrew install or upgrade
    @returns       the package names, without the options
    """
    return list(action.split_order) or [a for a in action.argv[action.split_head:] if not a.startswith("-")]


def _policy(names: Sequence[str]) -> OnFailure:
    """Return how a reinstall reacts to a failure: a batch splits, a single name is probed

    @param names  the names of the reinstall
    @returns      `SPLIT` for more than one name, else `PROBE`
    """
    return OnFailure.SPLIT if len(names) > 1 else OnFailure.PROBE


def adopted_tokens(run) -> set[str]:
    """Return the cask tokens phase 3 adopts, read from the ids of its adoptions

    An adoption's id is `3.adopt.<token>`.

    @param run  the run
    @returns    the tokens
    """
    return {a.action_id[len("3.adopt."):] for a in run.actions(3) if a.action_id.startswith("3.adopt.")}


def reinstall_split(run, target: Instance, action: Action, before: dict[str, Any]
                    ) -> tuple[list[str], list[str], list[str]]:
    """Return the formulae and casks the action may have poured, to reinstall, and the names left to install

    What it poured shows against the listing journaled before its first attempt; an adopted token never counts.

    @param run     the run
    @param target  the Homebrew target
    @param action  the unfinished batch install
    @param before  the listing journaled before its first attempt
    @returns       the formulae and the cask tokens to reinstall, then the names to install
    """
    catalogue = run.bundle.catalogue(target.prefix) if run.bundle is not None else None
    cellar, caskroom = read_listing(target.prefix)
    old_cellar = before.get("cellar") or {}
    old_rooms = before.get("caskroom") or {}
    casks = action.action_id == "3.install.casks"
    formulae: list[str] = []
    tokens: list[str] = []
    rest: list[str] = []
    racks: set[str] = set()
    for name in batch_names(action):
        if casks:
            token = (catalogue.canonical(name, "cask") if catalogue is not None else None) or name
            (tokens if token in caskroom else rest).append(name)
            continue
        rack = (catalogue.canonical(name) if catalogue is not None else None) or name
        version = catalogue.version(name) if catalogue is not None else None
        kegs = cellar.get(rack, [])
        poured = version in kegs if version else any(v not in old_cellar.get(rack, []) for v in kegs)
        if poured:
            formulae.append(name)
            racks.add(rack)
        else:
            rest.append(name)
    for rack, versions in sorted(cellar.items()):
        if rack not in racks and any(v not in old_cellar.get(rack, []) for v in versions):
            formulae.append(rack)
    adopted = adopted_tokens(run)
    for token in sorted(caskroom):
        if token not in old_rooms and token not in tokens and token not in adopted:
            tokens.append(token)
    return formulae, tokens, rest


def _rest_action(target: Instance, host_arch: str, action: Action, names: Sequence[str]) -> Action:
    """Return the command of an unfinished batch over the names it did not pour

    @param target     the Homebrew target
    @param host_arch  the host's architecture
    @param action     the unfinished batch
    @param names      the names left to install
    @returns          a command of the batch's own kind: an upgrade, a cask install or a formula install
    """
    aid = action.action_id
    if aid == "3.upgrade.formulae":
        return brew_actions.upgrade_formulae(target, host_arch, aid + ".upgrade", names)
    if aid == "3.install.casks":
        return brew_actions.install_casks(target, host_arch, aid + ".install", names)
    return brew_actions.install_formulae(target, host_arch, aid + ".install", names)


def resume_batch(run, target: Instance, action: Action, before: dict[str, Any]) -> None:
    """Re-run an unfinished Homebrew install as a reinstall of what it may have poured

    The original command installs the rest; the install keeps its own result line.

    @param run     the run
    @param target  the Homebrew target
    @param action  the unfinished batch install
    @param before  the listing journaled before its first attempt
    """
    formulae, tokens, rest = reinstall_split(run, target, action, before)
    host = run.runner.host_arch
    subs = []
    if formulae:
        subs.append(brew_actions.reinstall(target, host, action.action_id + ".reinstall", formulae,
                                           on_failure=_policy(formulae)))
    if tokens:
        subs.append(brew_actions.reinstall(target, host, action.action_id + ".reinstall-casks", tokens, kind="cask",
                                           on_failure=_policy(tokens)))
    if rest:
        subs.append(_rest_action(target, host, action, rest))
    run.say(f"  {action.action_id} did not finish in an earlier attempt: re-run as")
    for sub in subs:
        run.show(sub)
    results = [run.runner.run(sub, defer_result=True) for sub in subs]
    run.runner.record_result(action, all(r.ok for r in results))
    for sub, result in zip(subs, results):
        run.result_line(sub, result)


# Rebuilds ------------------------------------------------------------------------------------

def rebuild_name(action: Action) -> str | None:
    """Return the package a phase 3 rebuild names

    A rebuild's id is `3.<package>.rebuild`.

    @param action  a phase 3 action
    @returns       the package, or None for an action that is not a rebuild
    """
    aid = action.action_id
    if aid.startswith("3.") and aid.endswith(".rebuild"):
        return aid[len("3."):-len(".rebuild")]
    return None


def rebuild_clean(run, target: Instance, name: str) -> bool:
    """Return whether a rebuild passes its post-check

    The linkage scan of the package's current keg or active row must find no `missing` or cross-prefix reference.

    @param run     the run
    @param target  the target instance
    @param name    the rebuilt package
    @returns       False also when the package's binaries cannot be listed
    """
    brew = target.manager is Manager.BREW
    binaries = doctor.formula_binaries(target, name) if brew else doctor.port_binaries(target, name)
    if binaries is None:
        return False
    key = f"{target.prefix}|{'formula' if brew else 'port'}|{name}"
    report = env_linkage.scan(run.runner, {key: binaries}, run.instances)
    index = env.PrefixIndex(run.instances)
    for item in (report.get("binaries") or {}).values():
        for ref in item.get("references") or []:
            if ref.get("class") == "missing" or doctor.cross_reference(ref, item.get("instance_prefix")
                                                                      or target.prefix, index):
                return False
    return True


def rebuild(run, target: Instance, action: Action, name: str) -> None:
    """Run a rebuild; the rescan of its linkage, not its exit status, decides its result line

    @param run     the run
    @param target  the target instance
    @param action  the rebuild
    @param name    the package it rebuilds
    """
    result = run.runner.run(action, defer_result=True)
    run.rebuilt.add(name)
    clean = rebuild_clean(run, target, name)
    run.runner.record_result(action, clean)
    if clean:
        run.say(f"  {action.action_id}: ok")
    else:
        why = "the rescan still finds a broken reference" if result.ok else "the command failed"
        run.say(f"  {action.action_id}: failed ({why})")


def rebuild_action(run, target: Instance, name: str, variants: Sequence[str]) -> Action:
    """Return the rebuild of a target package: `brew reinstall`, or the missing-image remedy pair

    Its id is `3.<package>.rebuild`; the MacPorts pair runs in trace mode while a Homebrew prefix exists.

    @param run       the run
    @param target    the target instance
    @param name      the package
    @param variants  the package's requested variants, for MacPorts
    @returns         the rebuild
    """
    host = run.runner.host_arch
    action_id = f"3.{name}.rebuild"
    if target.manager is Manager.BREW:
        return brew_actions.reinstall(target, host, action_id, [name], on_failure=OnFailure.PROBE)
    return mp_actions.upgrade_forced(target, host, action_id, name, variants, homebrew_present=run.homebrew_present)


def dependents(run, target: Instance, upgraded: set[str]) -> dict[str, tuple[list[str], list[str]]]:
    """Return the target packages that depend on a `target_upgrades` package, with binaries and variants

    Homebrew's come from the receipts of the Cellar's current kegs, MacPorts' from the registry's active rows.

    @param run       the run
    @param target    the target instance
    @param upgraded  the `target_upgrades` names, in lower case
    @returns         the binaries and the requested variants by package; empty when the registry cannot be read
    """
    out: dict[str, tuple[list[str], list[str]]] = {}
    if target.manager is Manager.BREW:
        racks, _ = brew_inventory.walk_cellar(target.prefix)
        for name, rack in sorted(racks.items()):
            choice = brew_inventory.choose_kegs(target.prefix, [name], rack)
            deps = brew_inventory.receipt_dependencies(choice.receipt)
            if choice.current is not None and {d.lower() for d in deps} & upgraded:
                out[name] = (env_linkage.keg_binaries(choice.current.path), [])
        return out
    if target.portdbpath is None:
        raise ValueError(f"the MacPorts target {target.prefix} has no portdbpath")
    try:
        reg = registry.Registry.open_copy(target.portdbpath)
    except REGISTRY_ERRORS as exc:
        run.say(f"  the registry of {target.prefix} cannot be read ({exc}): no dependent is scanned")
        return out
    with reg:
        recorded = reg.dependencies()
        for row in reg.ports():
            if row.active and {d.lower() for d in recorded.get(row.id, [])} & upgraded:
                out[row.name] = ([f.location for f in reg.files(row.id) if f.binary and f.active],
                                 row.requested_variant_tokens)
    return out


def rescan(run, target: Instance, confirmed: bool) -> None:
    """Rebuild every installed dependent of a `target_upgrades` package with a `missing` reference

    Each runs as `3.<package>.rebuild`, so a resumed run, whose rescan finds fewer, keeps the ids it finds.

    @param run        the run
    @param target     the target instance
    @param confirmed  whether phase 3 has had its confirmation, so the rebuilds ask no question of their own
    """
    upgraded = {n.lower() for n in run.plan.target_upgrades}
    if not upgraded:
        return
    found = dependents(run, target, upgraded)
    kind = "formula" if target.manager is Manager.BREW else "port"
    report = env_linkage.scan(run.runner, {f"{target.prefix}|{kind}|{name}": bins
                                           for name, (bins, _) in sorted(found.items())}, run.instances)
    binaries = report.get("binaries") or {}
    todo = []
    for name, (bins, variants) in sorted(found.items()):
        broken = any(ref.get("class") == "missing" for path in bins
                     for ref in (binaries.get(path) or {}).get("references") or [])
        if not broken or name in run.rebuilt:
            continue
        action = rebuild_action(run, target, name, variants)
        run.show(action, skipped=run.ok(3, action.action_id))
        if not run.ok(3, action.action_id):
            todo.append((name, action))
    run.say(f"  dependents of upgraded packages: {len(found)} scanned, {len(todo)} to rebuild")
    if todo and not confirmed:
        run.confirm(3)
    for name, action in todo:
        rebuild(run, target, action, name)


# Phase 3 -------------------------------------------------------------------------------------

def run_install(run, target: Instance, action: Action) -> None:
    """Run one phase 3 action: a resumed batch as its reinstall, a rebuild with its post-check, else as planned

    A Homebrew batch journals the Cellar listing before its first attempt.

    @param run     the run
    @param target  the target instance
    @param action  the action
    """
    if target.manager is Manager.BREW and action.action_id in BREW_BATCHES:
        if action.action_id in run.listings:
            resume_batch(run, target, action, run.listings[action.action_id])
            return
        journal_listing(run, target, action)
    name = rebuild_name(action)
    if name is not None:
        rebuild(run, target, action, name)
        return
    run.result_line(action, run.runner.run(action))


def install(run) -> None:
    """Run phase 3: the plan's actions, none of which stops the phase, then the broken dependents' rebuilds

    @param run  the run
    """
    target = run.target
    pending = []
    for action in run.actions(3):
        done = run.ok(3, action.action_id)
        run.show(action, skipped=done)
        if not done:
            pending.append(action)
    if run.plan.target_upgrades:
        upgrades = ", ".join(run.plan.target_upgrades)
        run.say(f"  then the linkage scan of the installed dependents of {upgrades}; each with a missing reference is "
                "rebuilt")
    elif not pending:
        run.say("  nothing to install")
    if run.dry_run or target is None:
        return
    if pending:
        run.confirm(3)
    for action in pending:
        run_install(run, target, action)
    rescan(run, target, confirmed=bool(pending))

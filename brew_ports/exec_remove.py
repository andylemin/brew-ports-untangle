"""Phase 5 of `apply`: remove the source packages

Every start expands the removal set against the live inventory, so its journal entries are records, never skip rules.
"""

from __future__ import annotations

import itertools
import os
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import plan_sets, servicectl, state, system
from .exec_run import EXIT_ACTION, Stop, phase6_prefixes
from .homebrew import actions as brew_actions, inventory as brew_inventory
from .macports import actions as mp_actions, registry
from .model import Action, Instance, Manager, OnFailure, Service
from .plan_sets import name_key
from .runner import RM

CHSH = system.CHSH
ETC_SHELLS = "/etc/shells"
LINK_DIRS = ("bin", "sbin", "lib", "include", "share", "etc", "opt", "Frameworks")
REGISTRY_ERRORS = (registry.RegistryBusy, sqlite3.DatabaseError, OSError)

Key = tuple[str, str, str]          # (fresh prefix, kind, name key)


# The removal order ------------------------------------------------------------------------------

def _components(names: Sequence[str], edges: Mapping[str, set[str]]) -> list[list[str]]:
    """Return Tarjan's strongly connected components, without recursion

    Each component comes out after every component it depends on.

    @param names  the nodes, in the order the search starts from them
    @param edges  the nodes each node depends on
    @returns      the components, dependencies first
    """
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    out: list[list[str]] = []
    for root in names:
        if root in index:
            continue
        index[root] = low[root] = len(index)
        stack.append(root)
        on_stack.add(root)
        work = [(root, iter(sorted(edges[root])))]
        while work:
            node, children = work[-1]
            descended = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = len(index)
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(edges[child]))))
                    descended = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if descended:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    item = stack.pop()
                    on_stack.discard(item)
                    component.append(item)
                    if item == node:
                        break
                out.append(component)
    return out


def dependents_first(names: Sequence[str], deps: Mapping[str, Iterable[str]]) -> list[str]:
    """Return the `split_order` of a removal: every package before the packages of the set it depends on

    Unrelated packages and the members of a cycle keep their listed order.

    @param names  the packages of the removal, in listed order
    @param deps   each package's dependencies; those outside the set do not count
    @returns      the packages, dependents first
    """
    position = {name: i for i, name in enumerate(names)}
    edges = {name: {d for d in deps.get(name, ()) if d in position and d != name} for name in names}
    components = _components(list(names), edges)
    owner = {name: i for i, comp in enumerate(components) for name in comp}
    needs: dict[int, set[int]] = {i: set() for i in range(len(components))}
    for name, targets in edges.items():
        needs[owner[name]].update(owner[t] for t in targets if owner[t] != owner[name])
    waiting = {i: 0 for i in needs}
    for dep in itertools.chain.from_iterable(needs.values()):
        waiting[dep] += 1
    first = {i: min(position[n] for n in comp) for i, comp in enumerate(components)}
    ready = [i for i, count in waiting.items() if count == 0]
    out: list[str] = []
    while ready:
        ready.sort(key=first.__getitem__)
        current = ready.pop(0)
        out.extend(sorted(components[current], key=position.__getitem__))
        for dep in needs[current]:
            waiting[dep] -= 1
            if waiting[dep] == 0:
                ready.append(dep)
    return out


# The expansion against the live inventory ------------------------------------------------------

@dataclass
class Removal:
    """What phase 5 removes from one source instance, as the live inventory holds it"""

    inst: Instance
    adopted: list[str] = field(default_factory=list)       # Caskroom entries: the source records dropped
    casks: list[str] = field(default_factory=list)         # Caskroom entries, the names `brew uninstall` resolves
    formulae: list[str] = field(default_factory=list)      # racks, the names `brew uninstall` resolves
    ports: list[list[str]] = field(default_factory=list)   # spec_args of every installed version
    cask_order: list[str] = field(default_factory=list)
    formula_order: list[str] = field(default_factory=list)
    port_order: list[str] = field(default_factory=list)
    formula_names: dict[str, str] = field(default_factory=dict)  # rack -> its removal set name, where they differ
    cask_tokens: dict[str, str] = field(default_factory=dict)    # Caskroom entry -> the same, for a cask

    @property
    def empty(self) -> bool:
        """Return whether nothing of the instance is left to remove

        @returns  True when every list of packages is empty
        """
        return not (self.adopted or self.casks or self.formulae or self.ports)

    def keys(self) -> set[Key]:
        """Return the `(prefix, kind, name key)` of every package left to remove; an adopted cask counts as a cask

        A key holds the removal set name, which the services carry, not the name of the rack or Caskroom entry.

        @returns  the keys, as `service_key` makes them
        """
        prefix = self.inst.prefix
        out = {(prefix, "cask", self.cask_tokens.get(t, t)) for t in self.adopted + self.casks}
        out |= {(prefix, "formula", self.formula_names.get(f, f)) for f in self.formulae}
        out |= {(prefix, "port", name_key("port", spec[0])) for spec in self.ports}
        return out

    def items(self) -> list[str]:
        """Return a `<kind> <name>` line for every package left to remove, a port's with its version

        @returns  the lines: adopted casks, casks, formulae, then ports
        """
        return ([f"cask-adopted {t}" for t in self.adopted] + [f"cask {t}" for t in self.casks]
                + [f"formula {f}" for f in self.formulae] + [f"port {s[0]} {s[1]}" for s in self.ports])


def _scanned(run, prefix: str, kind: str) -> dict[str, Any]:
    """Return the packages of one kind that the newest scan found in a prefix

    @param run     the run
    @param prefix  the instance's prefix
    @param kind    `formula` or `cask`
    @returns       the packages by name; empty before the first scan
    """
    packages = run.bundle.result.packages if run.bundle is not None else []
    return {p.name: p for p in packages if p.instance_prefix == prefix and p.kind == kind}


def _expand_brew(run, inst: Instance, pairs: Sequence[tuple[str, str]]) -> Removal:
    """Expand the pairs of a Homebrew source against its Cellar and Caskroom, whose walks skip rename links

    A formula is looked for in its rack of `ScanBundle.formula_racks`, a cask in its entry of
    `ScanBundle.cask_rooms`, else each under its own name. The retry order follows the receipts' and the scan's
    dependencies, and cask -> cask edges for the casks.

    @param run    the run
    @param inst   the source instance
    @param pairs  its `(kind, name)` pairs of the removal set
    @returns      what is installed of them
    """
    racks, _ = brew_inventory.walk_cellar(inst.prefix)
    rooms, _ = brew_inventory.walk_caskroom(inst.prefix)
    held = run.bundle.formula_racks(inst.prefix) if run.bundle is not None else {}
    entries = run.bundle.cask_rooms(inst.prefix) if run.bundle is not None else {}
    out = Removal(inst)
    for kind, name in pairs:
        if kind == "formula":
            rack = held.get(name, name)
            if rack in racks and rack not in out.formulae:
                out.formulae.append(rack)
                if rack != name:
                    out.formula_names[rack] = name
        elif kind in ("cask", "cask-adopted"):
            room = entries.get(name, name)
            listed = out.casks if kind == "cask" else out.adopted
            if room in rooms and room not in listed:
                listed.append(room)
                if room != name:
                    out.cask_tokens[room] = name
    formulae = _scanned(run, inst.prefix, "formula")
    casks = _scanned(run, inst.prefix, "cask")
    deps: dict[str, set[str]] = {}
    for rack in out.formulae:
        name = out.formula_names.get(rack, rack)
        found = set(formulae[name].deps) if name in formulae else set()
        for keg in racks[rack].kegs:
            found.update(brew_inventory.receipt_dependencies(keg.receipt))
        deps[rack] = {held.get(d, d) for d in found}
    out.formula_order = dependents_first(out.formulae, deps)
    cask_deps: dict[str, set[str]] = {}
    for room in out.casks:
        token = out.cask_tokens.get(room, room)
        found = set(casks[token].cask_deps if token in casks else [])
        found.update(brew_inventory.receipt_dependencies(rooms[room].receipt, "cask"))
        cask_deps[room] = {entries.get(d, d) for d in found}
    out.cask_order = dependents_first(out.casks, cask_deps)
    return out


def _expand_ports(inst: Instance, pairs: Sequence[tuple[str, str]]) -> Removal:
    """Expand the `port` pairs against the registry rows of every state, case-insensitively as MacPorts does

    The retry order follows the `dependencies` table over every row.

    @param inst   the source instance
    @param pairs  its `(kind, name)` pairs of the removal set
    @returns      every installed version of the ports; nothing when the registry is gone and the inventory known
    @throws Stop  exit 4 when the registry is missing and the packages unknown, or the registry cannot be read
    """
    out = Removal(inst)
    wanted = {name_key("port", n) for k, n in pairs if k == "port"}
    try:
        reg = registry.Registry.open_copy(inst.portdbpath or "")
    except registry.RegistryMissing:
        if inst.inventory_known:
            return out
        raise Stop(EXIT_ACTION, [f"the registry of {inst.prefix} is missing and its packages are unknown: nothing was "
                                 "removed from it"]) from None
    except REGISTRY_ERRORS as exc:
        raise Stop(EXIT_ACTION, [f"the registry of {inst.prefix} cannot be read ({type(exc).__name__}: {exc}): "
                                 "nothing was removed from it"]) from None
    with reg:
        rows = [r for r in reg.ports() if r.name.lower() in wanted]
        recorded = reg.dependencies()
    names: list[str] = []
    needs: dict[str, set[str]] = {}
    for row in rows:
        out.ports.append(row.spec_args)
        if row.name not in names:
            names.append(row.name)
        needs.setdefault(row.name, set()).update(d.lower() for d in recorded.get(row.id, []))
    spelled: dict[str, list[str]] = {}
    for name in names:
        spelled.setdefault(name.lower(), []).append(name)
    deps = {name: {m for d in needs[name] for m in spelled.get(d, [])} for name in names}
    out.port_order = dependents_first(names, deps)
    return out


def expand(run) -> list[Removal]:
    """Return every installed version of every pair, per source instance

    An instance whose phase 6 deletion has begun is skipped, since an earlier phase 5 emptied it.

    @param run    the run
    @returns      one removal per source instance with pairs
    @throws Stop  exit 4 when a source is not found or its registry cannot be read
    """
    out = []
    for prefix, pairs in sorted(run.plan.removal_set.items()):
        if not pairs or run.phase6_begun(prefix):
            continue
        inst = run.fresh_instance(prefix)
        if inst is None:
            raise Stop(EXIT_ACTION, [f"the source {prefix} is not found any more: nothing was removed from it"])
        out.append(_expand_brew(run, inst, pairs) if inst.manager is Manager.BREW else _expand_ports(inst, pairs))
    return out


# The login shell ---------------------------------------------------------------------------------

@dataclass
class ShellSwitch:
    """The switch of the user's login shell from a source executable to the target's of the same name"""

    user: str
    old: str
    new: str
    package: str | None


def shell_switch(run) -> ShellSwitch | None:
    """Return the login shell's switch to the target's executable of the same name, or None

    The shell switches when the run removes its package or its prefix.

    @param run  the run, after a scan
    @returns    the switch, or None when the shell stays
    """
    bundle = run.bundle
    environment = bundle.result.environment if bundle is not None else {}
    shell = environment.get("login_shell")
    prefix = environment.get("login_shell_prefix")
    inst = run.instance(prefix) if prefix else None
    target = run.target
    if not shell or inst is None or target is None or inst.prefix == target.prefix:
        return None
    plan = run.plan
    pairs = [pair for p, ps in list(plan.removal_set.items()) + list(plan.path_removed.items())
             if run.instance(p) is inst for pair in ps]
    deleted = any(run.instance(p) is inst for p in phase6_prefixes(plan))
    if not pairs and not deleted:
        return None
    catalogue = bundle.catalogue(inst.prefix)

    def canonical(name: str, kind: str) -> str | None:
        return catalogue.canonical(name, kind) if catalogue is not None and kind in ("formula", "cask") else None
    graph = plan_sets.SourceGraph(inst, plan_sets.units_of(inst, bundle.result.packages), canonical)
    unit = plan_sets.package_at(graph, shell, environment.get("login_shell_realpath"), owner_of=bundle.owner_of)
    removed = {("cask" if k == "cask-adopted" else k, name_key(k, n)) for k, n in pairs}
    if not deleted and (unit is None or (unit.kind, name_key(unit.kind, unit.name)) not in removed):
        return None
    return ShellSwitch(run.user, shell, os.path.join(target.prefix, "bin", os.path.basename(shell)),
                       unit.name if unit is not None else None)


def _write_shells(run, switch: ShellSwitch) -> None:
    """Write `/etc/shells` with the new shell added, as root, journaled with its SHA-256

    @param run     the run
    @param switch  the switch, whose `new` shell is added
    """
    try:
        with open(ETC_SHELLS, encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        text = ""
    if switch.new in [line.strip() for line in text.splitlines()]:
        return
    content = text + ("" if not text or text.endswith("\n") else "\n") + switch.new + "\n"
    real = os.path.realpath(ETC_SHELLS)
    run.run_dir.etc_copy(real, "shells")   # the readable original that `rollback` replays
    digest = run.root_files().write(real, content, run.run_dir.path)
    action = Action(action_id=f"5.write.{state.slug(real)}", kind="write", argv=[], sudo=True,
                    description=f"add {switch.new} to {ETC_SHELLS}", dst=real, content=content)
    run.journal({"action_id": action.action_id, "kind": "write", "path": real, "named": ETC_SHELLS,
                 "sha256": digest, "root": True, "ops": [f"add {switch.new}"]})
    run.runner.record_result(action, True)


def switch_shell(run, switch: ShellSwitch) -> None:
    """Switch the login shell to the target's executable, journaling the old one for `rollback`

    A missing target executable stops the run before any removal.

    @param run     the run
    @param switch  the switch
    @throws Stop   exit 4 when the target has no executable of the shell's name
    """
    if not os.access(switch.new, os.X_OK):
        owner = switch.package or "a source prefix"
        raise Stop(EXIT_ACTION, [f"the login shell {switch.old} belongs to {owner}, which this run removes, and the "
                                 f"target has no executable {switch.new} to switch to: nothing was removed"])
    _write_shells(run, switch)
    run.journal({"action_id": "5.shell", "kind": "note", "user": switch.user, "from": switch.old, "to": switch.new})
    run.runner.run(Action(action_id="5.shell", kind="command", argv=[CHSH, "-s", switch.new, switch.user], sudo=True,
                          description=f"switch the login shell of {switch.user} from {switch.old} to {switch.new}"))
    run.say(f"  login shell of {switch.user}: {switch.old} -> {switch.new}")


# Services -----------------------------------------------------------------------------------------

def service_key(service: Service) -> Key:
    """Return the `(prefix, kind, name key)` of the package that owns a service

    @param service  the service
    @returns        the key, as `Removal.keys` makes it for the package
    """
    kind = service.package_kind or ""
    return (service.instance_prefix, kind, name_key(kind, service.package or ""))


def selected_services(run) -> list[Service]:
    """Return the owned services whose `(instance_prefix, package_kind, package)` is a pair of the removal set

    A `cask-adopted` pair stops nothing: its app is the target's.

    @param run  the run
    @returns    the services phase 5 stops; empty before the first scan
    """
    if run.bundle is None:
        return []
    pairs = {(run.fresh_prefix(p), k, name_key(k, n)) for p, ps in run.plan.removal_set.items() for k, n in ps
             if k != "cask-adopted"}
    return [s for s in run.bundle.result.services if s.owned and s.package and s.package_kind
            and service_key(s) in pairs]


def installed_keys(run) -> set[Key] | None:
    """Return the keys still installed, from a fresh expansion; None when that cannot be told

    @param run  the run
    @returns    the keys, or None when a source is not found or its registry cannot be read
    """
    try:
        return {key for removal in expand(run) for key in removal.keys()}
    except Stop:
        return None


def restart_remaining(run, booted: Sequence[Service]) -> None:
    """Start again every booted-out service whose package is still installed

    `servicectl.restart` runs in the runner's cleanup mode, so an interrupt does not leave them down.

    @param run     the run
    @param booted  the services phase 5 booted out
    """
    if not booted:
        return
    keys = installed_keys(run)
    remaining = [s for s in booted if keys is None or service_key(s) in keys]
    for service, ok in servicectl.restart(run.runner, remaining, run.instances, id_prefix="5"):
        outcome = "started again" if ok else f"could NOT be started again from {service.plist}"
        run.say(f"  {service.label} {outcome}")


# The removal ---------------------------------------------------------------------------------------

def links_into(prefix: str, room: str) -> list[str]:
    """Return every symlink under the prefix's link directories that resolves into a Caskroom entry

    @param prefix  the source prefix
    @param room    the Caskroom entry of one cask
    @returns       the links, sorted
    """
    real = os.path.realpath(room)
    out = []
    for sub in LINK_DIRS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(prefix, sub)):
            for name in dirnames + filenames:
                path = os.path.join(dirpath, name)
                if os.path.islink(path):
                    resolved = os.path.realpath(path)
                    if resolved == real or resolved.startswith(real + os.sep):
                        out.append(path)
    return sorted(out)


def adopted_token(run, inst: Instance, token: str) -> str:
    """Return the token the target holds an adopted source cask under: its mapping's target

    A cask rename or `--replace` gives the target token another name than the source's.

    @param run    the run
    @param inst   the source instance
    @param token  the source cask's token, as the removal set names it
    @returns      the target token; the source token when no adopting mapping names the cask
    """
    return next((m.target_name for m in run.plan.mappings if m.adopt and m.target_name and m.source.kind == "cask"
                 and m.source.name == token and run.fresh_prefix(m.source.instance_prefix) == inst.prefix), token)


def adopted_action(run, removal: Removal, room: str) -> Action | None:
    """Return the `rm -rf` of the source's record of an adopted cask, once the target's Caskroom holds it

    The target holds it under `adopted_token`. `brew uninstall --cask` would delete the bundle, which is the target's.

    @param run      the run
    @param removal  what is installed of the source
    @param room     the record: the cask's entry in the source's Caskroom
    @returns        the action, or None while the target's Caskroom lacks the cask
    """
    inst = removal.inst
    target = run.target
    token = adopted_token(run, inst, removal.cask_tokens.get(room, room))
    if target is None or not os.path.isdir(os.path.join(target.prefix, "Caskroom", token)):
        return None
    record = os.path.join(inst.prefix, "Caskroom", room)
    return Action(action_id=f"5.adopted.{room}", kind="command",
                  argv=[RM, "-rf"] + links_into(inst.prefix, record) + [record], sudo=False,
                  description=f"drop the record of the adopted cask {room} from {inst.prefix}",
                  on_failure=OnFailure.PROBE)


def uninstall_actions(run, removal: Removal) -> list[Action]:
    """Return the removal of the adopted records, then one uninstall per kind

    A failed uninstall retries one name at a time in dependents-first order.

    @param run      the run
    @param removal  what is installed of one source
    @returns        the actions, in the order they run
    """
    inst = removal.inst
    host = run.runner.host_arch
    out = [a for a in (adopted_action(run, removal, r) for r in removal.adopted) if a is not None]
    if removal.casks:
        out.append(brew_actions.uninstall_casks(inst, host, "5.uninstall.casks", removal.casks,
                                                split_order=removal.cask_order))
    if removal.formulae:
        out.append(brew_actions.uninstall_formulae(inst, host, "5.uninstall.formulae", removal.formulae,
                                                   split_order=removal.formula_order))
    if removal.ports:
        out.append(mp_actions.uninstall(inst, host, "5.uninstall.ports", removal.ports, split_order=removal.port_order))
    return out


def show_plan(run, steps: Sequence[tuple[Removal, list[Action]]], switch: ShellSwitch | None,
              services: Sequence[Service]) -> None:
    """Print what phase 5 is about to run; `--dry-run` stops after it

    @param run       the run
    @param steps     each source's removal with its actions
    @param switch    the login shell's switch, or None
    @param services  the services phase 5 stops
    """
    if switch is not None:
        run.say(f"  5.shell: add {switch.new} to {ETC_SHELLS} when it lacks it, then sudo {CHSH} -s {switch.new} "
                f"{switch.user}")
    for service in services:
        where = service.domain or ("system" if service.scope == "system" else "gui/<uid> or user/<uid>")
        sudo = "sudo " if where == "system" else ""
        run.say(f"  5.stop.{service.label}: {sudo}launchctl bootout {where}/{service.label}, then wait for it to exit")
    for removal, actions in steps:
        ids = {a.action_id for a in actions}
        for room in removal.adopted:
            if f"5.adopted.{room}" not in ids:
                token = adopted_token(run, removal.inst, removal.cask_tokens.get(room, room))
                run.say(f"  5.adopted.{room}: the target's Caskroom does not hold {token}, so the record in "
                        f"{removal.inst.prefix} stays")
        for action in actions:
            run.show(action)
    if services:
        run.say("  then the plists of the services whose packages are gone are deleted")


def finish(run, services: Sequence[Service]) -> None:
    """Expand again and delete the plists of the services whose packages are gone

    A package still installed stops the run before phases 6 and 7 can touch the prefix or the environment.

    @param run       the run
    @param services  the services phase 5 stopped
    @throws Stop     exit 4 when a package of the removal set is still installed
    """
    after = expand(run)
    left = {key for removal in after for key in removal.keys()}
    gone = [s for s in services if service_key(s) not in left]
    for service, deleted in servicectl.delete_plists(run.runner, gone, id_prefix="5"):
        if not deleted:
            run.say(f"  could not delete the plist {service.plist}")
    items = [f"{item} ({removal.inst.prefix})" for removal in after for item in removal.items()]
    if items:
        raise Stop(EXIT_ACTION, [f"phase 5 left {len(items)} package(s) installed:"] + [f"  {i}" for i in items]
                   + ["a dependent installed since the plan, or a bundle Homebrew cannot remove without sudo, can "
                      "hold one back; their services were started again"])


def remove(run) -> None:
    """Run phase 5: switch the login shell, stop the owned services, uninstall, then check what is left

    @param run    the run
    @throws Stop  exit 4 when a source cannot be expanded, the shell cannot switch, a service does not stop
                  (before any package is removed) or a package is left after the uninstalls
    """
    steps = [(r, uninstall_actions(run, r)) for r in expand(run) if not r.empty]
    switch = shell_switch(run)
    services = selected_services(run)
    if not steps and switch is None and not services:
        run.say("  nothing of the removal set is installed")
        return
    show_plan(run, steps, switch, services)
    if run.dry_run:
        return
    run.confirm(5)
    if switch is not None:
        switch_shell(run, switch)
    stopped: servicectl.StopResult | None = None
    done = False
    try:
        stopped = servicectl.stop(run.runner, services, run.uid, id_prefix="5")
        if stopped.error is not None:
            raise stopped.error
        if stopped.still_running:
            raise Stop(EXIT_ACTION, [f"{s.label}: {why}" for s, why in stopped.still_running]
                       + ["a service did not stop: nothing was removed"])
        for _, actions in steps:
            for action in actions:
                run.result_line(action, run.runner.run(action))
        finish(run, services)
        done = True
    finally:
        if not done:
            restart_remaining(run, stopped.booted if stopped is not None else [])

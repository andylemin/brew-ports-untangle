"""The text report of `plan`: mappings, roots, the kept and removal sets, casks, upgrades and phases"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from . import doctor, plan_sets, report
from .model import Phase
from .plan_sets import DROPPED, UNMIGRATABLE, WITHDRAWN

EVIDENCE_LINES = 3
EXECUTOR_PHASES = {0: "computed by apply", 1: "computed by apply", 4: "computed by apply",
                   5: "computed by apply from the removal set", 7: "computed by apply from the survivor set",
                   8: "computed by apply"}


def _instance_line(inst: Any) -> str:
    """Return how the report names an instance: its manager, prefix, version and usability

    @param inst  an instance
    @returns     `<manager> <prefix> <version> (<usability>)`, `undrivable` added when it cannot be driven
    """
    state = inst.usability.value if inst.drivable else f"{inst.usability.value}, undrivable"
    return f"{inst.manager.value} {inst.prefix} {inst.version or ''} ({state})"


def _header(draft: Any) -> list[str]:
    """Return the report's opening lines: the target, then each source

    @param draft  the planner's draft
    @returns      the lines; only `plan` without a target
    """
    if draft.target is None:
        return ["plan"]
    lines = [f"plan: target {_instance_line(draft.target)}"]
    lines += [f"  source {_instance_line(s)}" for s in draft.sources] or ["  no source instance"]
    return lines


def _mappings(draft: Any) -> list[str]:
    """Return the table of the accepted mappings, with the first evidence lines of each

    @param draft  the planner's draft
    @returns      the lines; none without a plan or a mapping
    """
    plan = draft.plan
    if plan is None or not plan.mappings:
        return []
    rows = []
    for m in plan.mappings:
        target = f"{m.target_kind} {m.target_name}{' (adopt)' if m.adopt else ''}"
        if m.companions:
            target += " + " + ", ".join(m.companions)
        rows.append((f"{m.source.name} ({m.source.instance_prefix})", target, m.confidence.name,
                     "; ".join(m.evidence[:EVIDENCE_LINES])))
    return ["", "Mappings"] + ["  " + line for line in report.table(rows, ["source", "target", "confidence",
                                                                           "evidence"])]


def _roots(draft: Any) -> list[str]:
    """Return the unmigratable, dropped and withdrawn roots, each with its note and whether it stays

    @param draft  the planner's draft
    @returns      the lines; none when every root migrates
    """
    rows = []
    for _, root in sorted(draft.roots.items()):
        if root.status in (UNMIGRATABLE, DROPPED, WITHDRAWN):
            state = "removed without a replacement" if root.status == DROPPED else "kept"
            rows.append(f"  {root.unit.label()}: {root.note} ({state})")
    return ["", "Unmigratable roots"] + rows if rows else []


def _kept(draft: Any) -> list[str]:
    """Return the kept set, each package with its reason

    @param draft  the planner's draft
    @returns      the lines; none when nothing is kept
    """
    sets = draft.sets
    if sets is None or not sets.kept:
        return []
    lines = ["", "Kept (still provided by their source)"]
    for key in sorted(sets.kept):
        lines.append(f"  {key[1]} {_name(draft, key)} ({key[0]}): {sets.kept[key]}")
    return lines


def _name(draft: Any, key: plan_sets.Key) -> str:
    """Return a unit's name as its source spells it

    @param draft  the planner's draft, whose units hold the names
    @param key    the unit's key
    @returns      the name; the key's name key when the draft lacks the unit
    """
    unit = draft.units.get(key)
    return unit.name if unit is not None else key[2]


def _pairs(title: str, table: dict[str, list[plan_sets.Pair]]) -> list[str]:
    """Return a section of removal pairs: a count per prefix, then the names by kind

    @param title  the section's heading
    @param table  the pairs by prefix
    @returns      the lines; none for an empty table
    """
    if not table:
        return []
    lines = ["", title]
    for prefix, pairs in sorted(table.items()):
        lines.append(f"  {prefix}: {len(pairs)}")
        groups: dict[str, list[str]] = {}
        for kind, name in pairs:
            groups.setdefault(kind, []).append(name)
        for kind in sorted(groups, key=lambda k: plan_sets.KIND_ORDER.get(k, 9)):
            lines.append(f"    {kind}: {', '.join(groups[kind])}")
    return lines


def _casks(draft: Any) -> list[str]:
    """Return the manual casks with their uninstall commands, and the removed casks with their homepages

    @param draft  the planner's draft
    @returns      the lines; none without such casks
    """
    sets = draft.sets
    if sets is None:
        return []
    lines: list[str] = []
    if sets.manual_casks:
        lines += ["", "Manual casks: Homebrew needs its own sudo to uninstall these; run on a terminal after the "
                      "migration"]
        lines += [f"  {u.inst.binary or u.prefix + '/bin/brew'} uninstall --cask {u.name}"
                  for u in sets.manual_casks]
    dropped = []
    for prefix, pairs in sorted(sets.removal.items()) + sorted(sets.path_removed.items()):
        for kind, name in pairs:
            if kind == "cask":
                unit = draft.units.get((prefix, "cask", name))
                homepage = unit.pkg.homepage if unit is not None and unit.pkg.homepage else "no homepage recorded"
                dropped.append(f"  {name} ({prefix}): reinstall by hand from {homepage}")
    if dropped:
        lines += ["", "Casks removed (their homepages, for a manual reinstall)"] + dropped
    return lines


def _left(draft: Any) -> list[str]:
    """Return the packages an undrivable source leaves in place, by prefix

    @param draft  the planner's draft
    @returns      the lines; none when nothing stays in place
    """
    sets = draft.sets
    if sets is None or not sets.left_in_place:
        return []
    groups: dict[str, list[str]] = {}
    for unit in sets.left_in_place:
        groups.setdefault(unit.prefix, []).append(unit.name)
    lines = ["", "Left in place (an undrivable source uninstalls nothing)"]
    lines += [f"  {prefix}: {', '.join(names)}" for prefix, names in sorted(groups.items())]
    return lines


def _upgrades(draft: Any) -> list[str]:
    """Return the table of the target upgrades, with their versions, reasons and pins

    @param draft  the planner's draft
    @returns      the lines; none without upgrades
    """
    ups = draft.upgrades
    if ups is None or not ups.names:
        return []
    rows = [(name, ups.versions.get(name, ""), ups.reasons.get(name, ""),
             "pinned" if name in ups.pinned else "") for name in ups.names]
    return ["", "Target upgrades (installed in place)"] + ["  " + line for line in report.table(
        rows, ["package", "version", "why", ""])]


def _services(draft: Any) -> list[str]:
    """Return the owned services phase 5 stops, each with its package and data directories

    @param draft  the planner's draft
    @returns      the lines; none when phase 5 stops nothing
    """
    if not draft.stops:
        return []
    lines = ["", "Services phase 5 stops"]
    for svc in draft.stops:
        data = f"; data: {', '.join(svc.data_dirs)}" if svc.data_dirs else ""
        lines.append(f"  {svc.label} ({svc.instance_prefix}, {svc.package_kind} {svc.package}){data}")
    return lines


def _phases(phases: Sequence[Phase]) -> list[str]:
    """Return the phases with their actions; a phase without actions says who computes it

    @param phases  the plan's phases
    @returns       the lines; none without phases
    """
    if not phases:
        return []
    lines = ["", "Phases"]
    for phase in phases:
        if phase.actions:
            lines.append(f"  {phase.number} {phase.name}: {len(phase.actions)} action(s)")
            for action in phase.actions:
                tag = "preview: " if action.manual and action.kind == "command" else ""
                lines.append(f"      {tag}{doctor.describe(action)}")
        else:
            lines.append(f"  {phase.number} {phase.name}: {EXECUTOR_PHASES.get(phase.number, 'nothing to do')}")
    return lines


def render(draft: Any) -> list[str]:
    """Return the report lines of a draft: what the plan does, then why it is refused when it is

    @param draft  the planner's draft
    @returns      the lines
    """
    lines = _header(draft)
    lines += _mappings(draft) + _roots(draft) + _kept(draft) + _left(draft)
    if draft.sets is not None:
        lines += _pairs("Removal set (every installed version of each)", draft.sets.removal)
        lines += _pairs("Removed with the prefix in phase 6", draft.sets.path_removed)
    lines += _casks(draft) + _upgrades(draft) + _services(draft)
    if draft.language_files:
        lines += ["", "Language packages"] + [f"  {kind}: {path}"
                                              for kind, path in sorted(draft.language_files.items())]
    if draft.plan is not None:
        lines += _phases(draft.plan.phases)
    if draft.notes:
        lines += ["", "Notes"] + [f"  {n}" for n in draft.notes]
    if draft.errors:
        lines += [""] + [f"brew-ports plan: {e}" for e in draft.errors]
    if draft.refusals:
        lines += ["", "Refused (exit 1)"] + [f"  {r}" for r in draft.refusals]
    return lines

"""What `plan` says: its overview, its questions, its report and its closing lines, in the reader's words"""

from __future__ import annotations

import shlex
from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Any

from . import doctor, plan_sets, report
from .equiv import rules
from .model import Confidence, Manager, Phase
from .plan_phases import PHASE_NAMES
from .plan_sets import DROPPED, MIGRATED, UNMIGRATABLE
from .report import COMMAND_OF, at, counted, manager_name, place, some, tilde

EVIDENCE_LINES = 3
COMMAND_WIDTH = 110                 # a command longer than this is cut in the default report
KIND_NOUNS = {"formula": ("formula", "formulae"), "cask": ("cask", "casks"), "port": ("port", "ports")}
INSTALL_KINDS = ("formula", "cask", "port")
MATCH_WORDS = {Confidence.EXACT: "same package", Confidence.HIGH: "known equivalent",
               Confidence.MEDIUM: "closest match", Confidence.LOW: "similar name"}
NEXT_HINT = "(lists every command, changes nothing)"
LANGUAGE_NAMES = {"pip": "Python", "cpan": "Perl", "gem": "Ruby"}


def holdings(units: Iterable[Any], inst: Any, unreadable: Iterable[str] = ()) -> str:
    """Return what an installation holds, by kind

    @param units       the units of every source
    @param inst        the installation
    @param unreadable  the prefixes of the installations whose package folders cannot be read
    @returns           such as `147 formulae, 5 casks`; `no packages`, or `its packages are unknown` when the scan
                       could not read them
    """
    if not inst.inventory_known or inst.prefix in unreadable:
        return "its packages are unknown"
    kinds = Counter(u.kind for u in units if u.prefix == inst.prefix)
    parts = [counted(kinds[kind], *KIND_NOUNS[kind]) for kind in INSTALL_KINDS if kinds[kind]]
    return ", ".join(parts) or "no packages"


def overview(draft: Any) -> list[str]:
    """Return what the plan moves where, and what becomes of each old installation

    Before the sets are settled the last line says what will be decided; after, it says what was.

    @param draft  the planner's draft, with its target
    @returns      the lines
    """
    scope = counted(len(draft.roots), "package") if draft.only else "every package"
    moves = not draft.settled or any(root.status == MIGRATED for root in draft.roots.values())
    lines = [f"Moving {scope} into {place(draft.target)}" if moves else f"No package moves into {place(draft.target)}"]
    stays = ", which stays installed" if draft.only else ""
    lines += [f"  from {place(inst)}{stays}: {holdings(draft.units.values(), inst, draft.unreadable)}"
              for inst in draft.sources]
    if not draft.settled:
        if draft.candidates:
            lines.append("  then uninstalling each old installation that the move leaves empty")
        return lines
    going = [inst for inst in draft.removed if inst.prefix not in draft.stays]
    if going:
        empty = ""
        if all(inst.drivable for inst in going):
            empty = f", which will {('', 'both ')[len(going) == 2] if len(going) < 3 else 'all '}be empty"
        lines.append(f"  then uninstalling {' and '.join(at(inst) for inst in going)}{empty}")
    lines += [f"  {at(inst)} {draft.stays[inst.prefix]}" for inst in draft.sources if inst.prefix in draft.stays]
    return lines


# The questions ------------------------------------------------------------------------------------

def owner(unit: Any) -> str:
    """Return a source package as the plan names it: its name, its version and its installation

    @param unit  the package's unit
    @returns     such as `giflib 4.2.3 (MacPorts at /opt/local)`
    """
    return f"{_versioned(unit)} ({at(unit.inst)})"


def _versioned(unit: Any) -> str:
    """Return a source package's name with its plain version

    @param unit  the package's unit
    @returns     such as `giflib 4.2.3`; the name alone without a version
    """
    version = rules.plain_version(unit.pkg.version)
    return f"{unit.name} {version}" if version else unit.name


def _replacement(mapping: Any) -> str:
    """Return a replacement's name with its plain version

    @param mapping  a mapping with a target
    @returns        such as `cmake 4.4.5`; the name alone without a version
    """
    version = rules.plain_version(mapping.target_version)
    return f"{mapping.target_name} {version}" if version else str(mapping.target_name)


def no_record_question(unit: Any) -> str:
    """Return the question about a package whose manager does not record whether it was asked for

    @param unit  the package's unit
    @returns     the question; yes gives it a replacement of its own, no treats it as a dependency
    """
    return (f"{owner(unit)}: {manager_name(unit.inst)} has no record of whether you installed it yourself.\n"
            "If you answer yes, it gets a replacement like every package you installed. If you answer no, it is "
            "treated as a dependency: it is uninstalled with the others and gets no replacement of its own.\n"
            "Did you install it yourself?")


def difference(unit: Any, mapping: Any) -> str:
    """Return how a closest match differs from the package it replaces, in plain words

    @param unit     the source package's unit
    @param mapping  its mapping
    @returns        the difference: the major version, else the name, else the matcher's reasons
    """
    old, new = rules.major(unit.pkg.version), rules.major(mapping.target_version)
    if old is not None and new is not None and old != new:
        side = "a newer" if new > old else "an older"
        return f"{side} major version, so programs built against {old}.x may not work with it"
    if (mapping.target_name or "").lower() != unit.name.lower():
        return "another name, for what looks like the same software"
    return "; ".join(mapping.evidence) or "the match is likely, not certain"


def medium_question(unit: Any, mapping: Any, target: Any) -> str:
    """Return the question about a likely but uncertain replacement

    @param unit     the source package's unit
    @param mapping  its closest match
    @param target   the target installation
    @returns        the question: what there is, the closest replacement and how it differs, what a no leads to,
                    then yes or no
    """
    replacement = _replacement(mapping)
    return (f"{owner(unit)}: {at(target)} has no exact match. The closest is {mapping.target_kind} "
            f"{replacement}: {difference(unit, mapping)}.\n"
            f"If you answer no, you choose next whether {unit.name} stays or is uninstalled.\n"
            f"Install {replacement} into {target.prefix} to replace it?")


def unmigratable_question(unit: Any, note: str, target: Any, *, emptied: bool, forced: bool = False,
                          manual: bool = False) -> str:
    """Return the question about a package without a replacement: keep it where it is, or drop it

    @param unit     the source package's unit
    @param note     why it has no replacement
    @param target   the target installation
    @param emptied  whether the plan uninstalls the package's installation once it is empty
    @param forced   whether `--delete` names that installation, which keeping the package then refuses
    @param manual   whether it is an app only the user can uninstall, so that dropping it gives a command to run
    @returns        the question
    """
    lines = [f"{owner(unit)} cannot move into {at(target)}: {note}."]
    if forced:
        lines.append(f"If you keep it, {at(unit.inst)} cannot be deleted, and --delete {unit.prefix} refuses the "
                     "plan.")
    elif emptied:
        lines.append(f"If you keep it, {at(unit.inst)} stays installed too.")
    drop = ("the plan then gives you the command to uninstall it, since Homebrew asks for your password" if manual
            else "uninstall it without a replacement")
    lines.append(f"Keep it in {at(unit.inst)}, or drop it ({drop})?")
    return "\n".join(lines)


# The report ---------------------------------------------------------------------------------------

def _included(mapping: Any) -> bool:
    """Return whether the replacement holds the package as a part, as a Python holds its `pip`

    @param mapping  an accepted mapping
    @returns        True when the matcher's first reason says so
    """
    return bool(mapping.evidence) and " is included in " in mapping.evidence[0]


def _renamed(root: Any) -> str:
    """Return a replacement under another name as the report lists it

    @param root  a migrated root whose replacement has another name
    @returns     such as `gsed is gnu-sed` or `py313-pip is part of python@3.13`
    """
    part = "part of " if _included(root.mapping) else ""
    return f"{root.unit.name} is {part}{root.mapping.target_name}"


def _to_install(draft: Any, roots: Sequence[Any]) -> list[str]:
    """Return the line that says which replacements the plan installs and which the target already has

    @param draft  the planner's draft
    @param roots  the migrated roots
    @returns      one line; none when no replacement is a package of the target
    """
    names: list[str] = []
    for root in roots:
        mapping = root.mapping
        if mapping.adopt:
            continue
        own = [mapping.target_name] if mapping.target_kind in INSTALL_KINDS else []
        for name in own + list(mapping.companions):
            if name and name not in names:
                names.append(name)
    if not names:
        return []
    have = {name.lower() for name in draft.installed}
    new = [name for name in names if name.lower() not in have]
    there = [name for name in names if name.lower() in have]
    if not new:
        return [f"  Nothing to install: {some(there)} {'is' if len(there) == 1 else 'are'} already there"]
    return [f"  To install: {some(new)}" + (f"; already there: {some(there)}" if there else "")]


def _replacements(draft: Any) -> list[str]:
    """Return the accepted replacements, grouped by how sure the match is

    @param draft  the planner's draft
    @returns      the lines; none when no package gets a replacement
    """
    roots = [root for _, root in sorted(draft.roots.items()) if root.status == MIGRATED and root.mapping is not None]
    if not roots:
        return []
    same, renamed, closest, adopted, tools = [], [], [], [], []
    for root in roots:
        mapping = root.mapping
        if mapping.adopt:
            adopted.append(root.unit.name)
        elif mapping.target_kind not in INSTALL_KINDS:
            tools.append(root.unit.name)
        elif mapping.confidence is Confidence.MEDIUM:
            closest.append(root)
        elif (mapping.target_name or "").lower() != root.unit.name.lower():
            renamed.append(root)
        else:
            same.append(root.unit.name)
    where = at(draft.target)
    lines = ["", f"Replacements in {where}: {counted(len(roots), 'package')}"]
    if same:
        lines.append(f"  {len(same)} under the same name: {some(same)}")
    if renamed:
        lines.append(f"  {len(renamed)} under another name: {some(_renamed(root) for root in renamed)}")
    if closest:
        how = "accepted by --accept-closest" if draft.accept_closest else "which you accepted"
        lines.append(f"  {len(closest)} by the closest match, {how}")
        lines += [f"      {_versioned(root.unit)} becomes {_replacement(root.mapping)}: "
                  f"{difference(root.unit, root.mapping)}" for root in closest]
    if adopted:
        one = len(adopted) == 1
        lines.append(f"  {counted(len(adopted), 'app')} {'stays where it is' if one else 'stay where they are'}; "
                     f"{where} takes over {'its' if one else 'their'} record: {some(adopted)}")
    if tools:
        lines.append(f"  {counted(len(tools), 'Python tool')} to reinstall with pipx: {some(tools)}")
    return lines + _to_install(draft, roots)


def _staying(draft: Any, whole: bool = False) -> list[str]:
    """Return what stays in each old installation and why, then what is uninstalled without a replacement

    @param draft  the planner's draft
    @param whole  name every package of a long group that shares a reason
    @returns      the lines; none when everything moves
    """
    sets = draft.sets
    if sets is None:
        return []
    lines: list[str] = []
    for inst in draft.sources:
        left = [unit.name for unit in sets.left_in_place if unit.prefix == inst.prefix]
        if left:
            lines += ["", f"Staying in {at(inst)}, whose `{COMMAND_OF[inst.manager]}` command cannot run",
                      f"  {counted(len(left), 'package')}: {some(left)}"]
            continue
        keys = sorted((key for key in sets.kept if key[0] == inst.prefix), key=lambda k: (k[1], k[2].lower()))
        own = [(_versioned(draft.units[key]) if key in draft.units else key[2], sets.kept[key])
               for key in keys if key not in sets.followers]
        own += [(unit.name, "only you can uninstall it; the command is below")
                for unit in sets.manual_casks if unit.prefix == inst.prefix]
        if not keys and not own:
            continue
        lines += ["", f"Staying in {at(inst)}"] + _by_reason(own, whole)
        needed = [_name(draft, key) for key in keys if key in sets.followers]
        if needed:
            lines.append(f"  and {counted(len(needed), 'package')} {'it needs' if len(own) == 1 else 'they need'}: "
                         f"{some(needed)}")
        if any(_droppable(draft.roots.get(key)) for key in keys):
            lines.append("  To move one of these after all, plan with `--replace NAME=OTHER`; to uninstall one without "
                         "a replacement, with `--uninstall NAME`")
    stay = set(sets.kept) | {unit.key for unit in sets.manual_casks} | {unit.key for unit in sets.left_in_place}
    dropped = [root for key, root in sorted(draft.roots.items()) if root.status == DROPPED and key not in stay]
    if dropped:
        lines += ["", "To uninstall without a replacement"]
        lines += [f"  {owner(root.unit)}: {root.note}" for root in dropped]
    return lines


def _by_reason(items: Sequence[tuple[str, str]], whole: bool = False) -> list[str]:
    """Return what stays and why: a line per package, and one line for the packages that share a reason

    @param items  `(name, reason)` of each package, in the order to show
    @param whole  name every package of a long group
    @returns      the lines
    """
    groups: dict[str, list[str]] = {}
    for name, why in items:
        groups.setdefault(why, []).append(name)
    lines = []
    for why, names in groups.items():
        if len(names) == 1:
            lines.append(f"  {names[0]}: {why}")
        elif whole or len(names) <= report.NAMES_SHOWN:
            lines += [f"  {counted(len(names), 'package')}: {why}", f"      {', '.join(names)}"]
        else:
            lines += [f"  {counted(len(names), 'package')}: {why}", f"      {some(names)} (--verbose lists all)"]
    return lines


def _droppable(root: Any) -> bool:
    """Return whether a package that stays is one `--replace` or `--uninstall` can still settle

    @param root  the package's root, or None when it is none
    @returns     True for a package without a replacement, except an app only the user can uninstall
    """
    return (root is not None and root.status == UNMIGRATABLE
            and not (root.unit.kind == "cask" and root.unit.pkg.privileged_uninstall))


def _name(draft: Any, key: plan_sets.Key) -> str:
    """Return a unit's name as its source spells it

    @param draft  the planner's draft, whose units hold the names
    @param key    the unit's key
    @returns      the name; the key's name key when the draft lacks the unit
    """
    unit = draft.units.get(key)
    return unit.name if unit is not None else key[2]


def _packages(pairs: Sequence[plan_sets.Pair]) -> str:
    """Return how many packages a list of removal pairs holds, by kind

    @param pairs  `(kind, name)` pairs, without adopted casks
    @returns      such as `91 ports` or `40 formulae, 2 casks`
    """
    kinds = Counter(kind for kind, _ in pairs)
    return ", ".join(counted(kinds[kind], *KIND_NOUNS[kind]) for kind in INSTALL_KINDS if kinds[kind])


def _by_kind(pairs: Iterable[plan_sets.Pair]) -> list[plan_sets.Pair]:
    """Return removal pairs in the order their counts are given: formulae, casks, ports

    @param pairs  `(kind, name)` pairs
    @returns      the pairs by kind, each kind in the order it came
    """
    pairs = list(pairs)
    return [pair for kind in INSTALL_KINDS for pair in pairs if pair[0] == kind]


def _is_dependency(draft: Any, prefix: str, pair: plan_sets.Pair) -> bool:
    """Return whether a package to uninstall came in as a dependency, by its manager's own record

    @param draft   the planner's draft, whose units hold the packages
    @param prefix  the installation's prefix
    @param pair    the package's `(kind, name)`
    @returns       True for a formula or port that its manager records as not installed by the user
    """
    unit = draft.units.get((prefix, pair[0], plan_sets.name_key(*pair)))
    return unit is not None and unit.kind != "cask" and unit.pkg.requested is False


def _uninstalls(draft: Any) -> list[str]:
    """Return what each old installation loses: its uninstalls, and what goes with one that is deleted whole

    @param draft  the planner's draft
    @returns      the lines; none without sets
    """
    sets = draft.sets
    if sets is None:
        return []
    lines: list[str] = []
    more = " (--verbose lists all)"
    for inst in draft.sources:
        pairs = _by_kind(pair for pair in sets.removal.get(inst.prefix, []) if pair[0] != "cask-adopted")
        if pairs:
            needed = sum(_is_dependency(draft, inst.prefix, pair) for pair in pairs)
            split = f", {needed} of them {'a dependency' if needed == 1 else 'dependencies'}" if (
                0 < needed < len(pairs)) else ""
            names = [name for _, name in pairs]
            lines += ["", f"To uninstall from {at(inst)}", f"  {_packages(pairs)}{split}",
                      f"      {some(names)}{more if len(names) > report.NAMES_SHOWN else ''}"]
        gone = _by_kind(pair for pair in sets.path_removed.get(inst.prefix, []) if pair[0] != "cask-adopted")
        if gone:
            names = [name for _, name in gone]
            lines += ["", f"To delete with {at(inst)}, whose `{COMMAND_OF[inst.manager]}` command cannot run",
                      f"  {_packages(gone)}: {some(names)}{more if len(names) > report.NAMES_SHOWN else ''}"]
    return lines


def _apps(draft: Any) -> list[str]:
    """Return the apps only the user can uninstall, with the commands, and the apps the plan uninstalls

    @param draft  the planner's draft
    @returns      the lines; none without such apps
    """
    sets = draft.sets
    if sets is None:
        return []
    lines: list[str] = []
    if sets.manual_casks:
        one = len(sets.manual_casks) == 1
        lines += ["", f"{'An app' if one else 'Apps'} only you can uninstall: Homebrew asks for your password "
                      f"itself. {'It stays' if one else 'They stay'} until you run"]
        held: dict[str, list[Any]] = {}
        for unit in sets.manual_casks:
            held.setdefault(unit.prefix, []).append(unit)
        lines += [f"  {plan_sets.uninstall_casks(units)}" for _, units in sorted(held.items())]
        lines.append("  Plan again afterwards: an installation that stays only for such an app can then go too")
    gone = []
    for prefix, pairs in sorted(sets.removal.items()) + sorted(sets.path_removed.items()):
        for kind, name in pairs:
            key = (prefix, "cask", plan_sets.name_key("cask", name))
            if kind == "cask" and key not in draft.roots:      # a root is under its replacement, or its own note
                unit = draft.units.get(key)
                homepage = unit.pkg.homepage if unit is not None and unit.pkg.homepage else "no homepage is recorded"
                gone.append(f"  {name}: {homepage}")
    if gone:
        title = ("An app to uninstall; to have it again, install it from its homepage" if len(gone) == 1
                 else "Apps to uninstall; to have one again, install it from its homepage")
        lines += ["", title] + gone
    return lines


def _upgrades(draft: Any) -> list[str]:
    """Return the packages of the target that the replacements upgrade, with their versions and reasons

    @param draft  the planner's draft
    @returns      the lines; none without upgrades
    """
    ups = draft.upgrades
    if ups is None or not ups.names:
        return []
    rows = [(name, ups.versions.get(name, ""), ups.reasons.get(name, "") + (", pinned" if name in ups.pinned else ""))
            for name in ups.names]
    return ["", f"Upgrades in {at(draft.target)} that the replacements need"] + [
        "  " + line for line in report.table(rows, ["package", "versions", "why"])]


def _services(draft: Any) -> list[str]:
    """Return the services of the packages to uninstall: whether each runs, its data, and what starts them again

    `apply` stops the running ones first. With `--start-services` it starts the replacement of each of those,
    except one that runs as root in Homebrew, whose command it prints.

    @param draft  the planner's draft
    @returns      the lines; none when no package to uninstall has a service
    """
    if not draft.stops:
        return []
    lines = ["", "Services of the packages to uninstall"]
    for svc in draft.stops:
        state = "running; it is stopped first" if svc.loaded else "not running"
        lines.append(f"  {svc.label} ({svc.package}): {state}")
        if svc.data_dirs:
            lines.append(f"      its data: {', '.join(svc.data_dirs)}")
    running = [svc for svc in draft.stops if svc.loaded]
    if not running:
        return lines
    one = len(running) == 1
    if not draft.start_services:
        return lines + [f"  {'Its replacement is' if one else 'Their replacements are'} not started: plan with "
                        f"--start-services to start {'it' if one else 'them'}"]
    lines.append(f"  The replacement of {'the running one' if one else 'each running one'} is started afterwards "
                 "(--start-services)")
    if draft.target.manager is Manager.BREW and any(svc.scope == "system" for svc in running):
        lines.append("  A service that runs as root is not started in Homebrew: `apply` prints the command for you")
    return lines


def _language(draft: Any) -> list[str]:
    """Return the lists of the language packages the plan does not move

    @param draft  the planner's draft
    @returns      the lines; none without such packages
    """
    if not draft.language_files:
        return []
    names = [LANGUAGE_NAMES.get(kind, kind) for kind in sorted(draft.language_files)]
    which = f"{', '.join(names[:-1])} and {names[-1]}" if len(names) > 1 else names[0]
    lists = "The list" if len(names) == 1 else "Lists"
    title = (f"Of the {which} packages, only the Python tools that pipx installs move. {lists} of them all"
             if draft.pipx else f"{which} packages are not moved. {lists} to reinstall them from")
    return ["", title] + [f"  {tilde(path)}" for _, path in sorted(draft.language_files.items())]


def _command(action: Any, whole: bool) -> str:
    """Return a planned command as the report shows it

    @param action  the action
    @param whole   show the command whole, however long it is
    @returns       the command as the user would type it, cut at a word when it is long
    """
    text = doctor.describe(action)
    if whole or len(text) <= COMMAND_WIDTH:
        return text
    words = text[:COMMAND_WIDTH].rsplit(" ", 1)[0]
    return f"{words} ... ({counted(len(text.split()) - len(words.split()), 'more word')}; --verbose shows all)"


def _uninstall_steps(draft: Any, phase: Phase) -> list[str]:
    """Return what phase 6 does to each old installation, from the plan's previews

    @param draft  the planner's draft
    @param phase  phase 6
    @returns      a line per installation, each followed by what stays of it and why
    """
    lines = []
    for inst in draft.removed:
        mine = [action for action in phase.actions if action.instance_prefix == inst.prefix]
        saved =["/" + action.argv[-1] for action in mine if action.action_id.startswith("6.archive.")]
        deleted = [action.argv[-1] for action in mine if action.action_id.startswith("6.delete.")]
        steps = ([f"save {some(saved, 4)} in the run folder"] if saved else []) + (
            [f"delete {some(deleted, 4)}"] if deleted else [])
        lines.append(f"  6  Uninstall {at(inst)}" + (f": {', then '.join(steps)}" if steps else ""))
        lines += [f"       {action.description}" for action in mine if ".skipped." in action.action_id]
    return lines


def _steps(draft: Any, verbose: bool) -> list[str]:
    """Return what `apply` will do, phase by phase

    @param draft    the planner's draft, with its plan
    @param verbose  show every command whole, and the notes of phase 6
    @returns        the lines; none without phases
    """
    phases = draft.plan.phases if draft.plan is not None else []
    if not phases:
        return []
    lines = ["", "What `brew-ports apply` will do, asking before each step that changes something"]
    for phase in phases:
        number = phase.number
        if number == 6:
            lines += _uninstall_steps(draft, phase)
            if verbose:
                lines += [f"       {action.description}" for action in phase.actions if action.kind == "note"
                          and ".job." not in action.action_id and ".skipped." not in action.action_id]
            continue
        if number == 2 and not phase.actions:
            continue
        name = f"Repair {at(draft.target)}" if number == 2 else PHASE_NAMES[number].capitalize()
        running = [svc for svc in draft.stops if svc.loaded]
        if number == 5 and running:
            name += f", after stopping {counted(len(running), 'service')}"
        lines.append(f"  {number}  {name}")
        commands = [_command(action, verbose) for action in phase.actions if action.kind == "command"]
        lines += [f"       {command}" for command in dict.fromkeys(commands)]
        if number == 3 and not phase.actions:
            lines.append("       nothing to install")
        if number == 5 and draft.sets is not None and not any(
                kind != "cask-adopted" for pairs in draft.sets.removal.values() for kind, _ in pairs):
            lines.append("       nothing to uninstall")
    return lines


def _matches(draft: Any) -> list[str]:
    """Return every accepted replacement with the matcher's reasons, for `--verbose`

    @param draft  the planner's draft
    @returns      the lines; none without a plan or a replacement
    """
    plan = draft.plan
    if plan is None or not plan.mappings:
        return []
    rows = []
    chosen = {pair.partition("=")[0].strip().lower() for pair in plan.options.get("map", "").split(",") if "=" in pair}
    for mapping in plan.mappings:
        target = f"{mapping.target_kind} {mapping.target_name}{' (taken over)' if mapping.adopt else ''}"
        if mapping.companions:
            target += " + " + ", ".join(mapping.companions)
        match = ("your choice" if mapping.source.name.lower() in chosen else "part of it" if _included(mapping)
                 else MATCH_WORDS.get(mapping.confidence, "none"))
        rows.append((mapping.source.name, mapping.source.instance_prefix, target, match,
                     "; ".join(mapping.evidence[:EVIDENCE_LINES])))
    table = report.table(rows, ["package", "from", "replacement", "match", "how it was found"])
    return ["", "Every replacement, and how it was found"] + ["  " + line for line in table]


def _every(draft: Any) -> list[str]:
    """Return the whole uninstall list of each old installation, for `--verbose`

    @param draft  the planner's draft
    @returns      the lines; none without sets
    """
    sets = draft.sets
    lines: list[str] = []
    for inst in draft.sources if sets is not None else []:
        for pairs, title in ((sets.removal, "Every package to uninstall from"),
                             (sets.path_removed, "Every package to delete with")):
            names = [name for kind, name in pairs.get(inst.prefix, []) if kind != "cask-adopted"]
            if len(names) > report.NAMES_SHOWN:
                lines += ["", f"{title} {at(inst)}", f"  {', '.join(names)}"]
    return lines


def render(draft: Any, verbose: bool = False) -> list[str]:
    """Return the report of a draft: what the plan does; the errors and refusals are `problems`

    @param draft    the planner's draft
    @param verbose  add every replacement with its reasons, the whole lists and the whole commands
    @returns        the lines; none when the plan stopped before it had a target
    """
    if draft.target is None or draft.errors:
        return []
    lines = overview(draft) + _replacements(draft) + _staying(draft, verbose) + _uninstalls(draft) + _apps(draft)
    lines += _upgrades(draft) + _services(draft) + _language(draft)
    if draft.todo:
        lines += ["", "To do before `brew-ports apply`"] + [f"  {task}" for task in draft.todo]
    if not draft.refusals:
        lines += _steps(draft, verbose)
    if draft.notes:
        lines += ["", "Good to know"] + [f"  {note}" for note in draft.notes]
    if verbose:
        lines += _matches(draft) + _every(draft)
    return lines


def problems(draft: Any) -> list[str]:
    """Return why there is no plan: the errors, or the things to settle first

    @param draft  the planner's draft
    @returns      the lines for the error stream, an indented line continuing the one above; none for a plan
    """
    if draft.errors:
        return [line if line.startswith(" ") else f"brew-ports: {line}" for line in draft.errors]
    if draft.refusals:
        count = counted(len(draft.refusals), "thing")
        return [f"brew-ports: no plan was made: {count} to settle first"] + [f"    {r}" for r in draft.refusals]
    return []


def closing(plan_file: str, out: str | None, run_folder: str, updated: str | None = None) -> list[str]:
    """Return the last lines of a plan that was made: where it is, what changed, and what to run next

    @param plan_file   the plan in the run folder
    @param out         the `--out` copy as the user named it, or None without one
    @param run_folder  the run folder
    @param updated     the installation whose package list `--refresh` updated, or None
    @returns           the lines
    """
    changed = (f"Only the package list of {updated} was updated; nothing else has changed on this Mac."
               if updated else "Nothing has changed on this Mac.")
    if out:
        lines = ["", f"Plan saved as {out}. {changed}", f"Run folder: {tilde(run_folder)}"]
    else:
        lines = ["", f"Plan saved in the run folder, {tilde(run_folder)}. {changed}"]
    return lines + [f"Next: brew-ports apply {shlex.quote(out or plan_file)} --dry-run   {NEXT_HINT}"]


def refused_closing(refused: str) -> list[str]:
    """Return the last line of a plan that was not made: where its reasons are kept

    @param refused  the file that holds the reasons
    @returns        the line
    """
    return [f"No plan was saved. The reasons are also in {tilde(refused)}."]

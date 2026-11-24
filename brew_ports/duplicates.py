"""Packages that are installed twice: in the installation that the user keeps and in another one

While both copies of a package are installed, one of them is broken: typing its command or building with it finds
only one of the two. `doctor --target` reports the copies outside the installation that stays and names how to
uninstall them.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field, replace

from . import doctor, doctor_report, plan_sets, recommend
from .equiv import resolver
from .homebrew import actions as brew_actions
from .model import Instance, Issue, Manager, Severity
from .plan_phases import TargetView
from .report import COMMAND_OF, NAMES_SHOWN, at, counted, some, typed

KINDS = ("formula", "port")         # an app is one copy in /Applications, whichever Homebrew recorded it
CODE = "env-installed-twice"        # the finding of `doctor --target`, one per other installation
WHY = ("While a package is installed twice, one copy is broken: typing its command or building with it finds only "
       "one of the two.")


@dataclass
class Double:
    """A package of another installation that the installation that stays has too"""

    other: Instance                 # the installation that holds the second copy
    name: str                       # the package's name there
    kept: str                       # the name of the copy in the installation that stays
    needed_by: list[str] = field(default_factory=list)      # the packages there that depend on that second copy
    version: str = ""               # a port's `@<version>_<revision><variants>`, which names the copy in use
    held: list[str] = field(default_factory=list)           # what else ties it there, as words that follow "it"

    def reasons(self) -> list[str]:
        """Return why the second copy is left to the move, which takes care of what depends on it

        @returns  each reason as the words that follow "it", such as `is your login shell`; none for a copy
                  that can be uninstalled alone
        """
        out = []
        if self.needed_by:
            out.append(f"is needed by {counted(len(self.needed_by), 'package')} there ({some(self.needed_by)})")
        out += self.held
        if not self.other.drivable:
            out.append(f"cannot be uninstalled while the `{COMMAND_OF[self.other.manager]}` command there does "
                       "not run")
        return out


def _graph(bundle, inst: Instance, units: list[plan_sets.Unit]) -> plan_sets.SourceGraph:
    """Return the dependency graph of one installation, a Homebrew's dependencies under their current names

    @param bundle  the scan
    @param inst    the installation
    @param units   its packages
    @returns       the graph
    """
    catalogue = bundle.catalogue(inst.prefix) if inst.manager is Manager.BREW else None

    def canonical(name: str, kind: str) -> str | None:
        return catalogue.canonical(name, kind) if catalogue is not None and kind in ("formula", "cask") else None
    return plan_sets.SourceGraph(inst, units, canonical)


def _login_shell(bundle, graphs: dict[str, plan_sets.SourceGraph]) -> plan_sets.Unit | None:
    """Return the package that provides the login shell, when one of the other installations holds it

    @param bundle  the scan
    @param graphs  the graphs of the other installations, by prefix
    @returns       the package, or None
    """
    environment = bundle.result.environment
    shell = environment.get("login_shell")
    graph = graphs.get(environment.get("login_shell_prefix") or "")
    if not shell or graph is None:
        return None
    return plan_sets.package_at(graph, shell, environment.get("login_shell_realpath"), bundle.owner_of)


def find(bundle, target: Instance) -> list[Double] | None:
    """Return the packages of the other installations that the installation that stays has too

    A package counts when `plan` replaces it by its default rules, with the same package or a known equivalent,
    and that replacement is installed in the target: a move would only uninstall the other copy. A port that is
    stored but not in use is no copy, and neither is an app.

    @param bundle  the scan
    @param target  the installation that stays
    @returns       the packages, installation by installation, in the order `plan` lists them; None when the
                   target has no package list to match the names against
    """
    result = bundle.result
    ctx = recommend.resolver_context(bundle, target.manager.value, target)
    listed = ctx.catalogue is not None and ctx.catalogue.source != "none"
    if not (listed if target.manager is Manager.BREW else ctx.portindex is not None):
        return None
    roots = plan_sets.plain_roots(result, target.prefix, target.manager)
    ctx.python_version = resolver.plan_python([unit.pkg for unit, _ in roots], ctx)
    view = TargetView(target, ctx.installed, ctx.catalogue, ctx.portindex)
    others = [inst for inst in result.instances if inst.prefix != target.prefix]
    units = {inst.prefix: plan_sets.units_of(inst, result.packages) for inst in others}
    graphs = {inst.prefix: _graph(bundle, inst, units[inst.prefix]) for inst in others}
    ties = plan_sets.Ties(result.services, plan_sets.extras_ties(result.interpreter_extras, units),
                          plan_sets.default_data_dirs)
    shell = _login_shell(bundle, graphs)
    out = []
    for inst in others:
        graph = graphs[inst.prefix]
        for unit in units[inst.prefix]:
            if unit.kind not in KINDS or unit.inactive_only:
                continue
            mapping = resolver.resolve(unit.pkg, ctx)
            kept = view.installed(mapping.target_name) if mapping.target_name else None
            if kept is None or mapping.target_kind not in KINDS or not resolver.accepted(mapping, ctx):
                continue
            users = sorted(graph.units[key].name for key in graph.dependents.get(unit.key, ()))
            version = unit.pkg.spec_args[1] if unit.kind == "port" and len(unit.pkg.spec_args) == 2 else ""
            held = (["is your login shell"] if unit is shell else []) + [f"has {tie}" for tie in ties.of(unit)]
            out.append(Double(inst, unit.name, kept.name, users, version, held))
    return out


def uninstall(double: Double, host_arch: str | None) -> str:
    """Return the command that uninstalls the other copy of a package, as the user types it

    A port is named with its version: where MacPorts also stores a version that is not in use, `port uninstall`
    refuses a name alone.

    @param double     a package that is installed twice
    @param host_arch  the Mac's architecture
    @returns          the command of the installation that holds the other copy
    """
    other = double.other
    if other.manager is Manager.BREW:
        return brew_actions.typed_line(other, ["uninstall", "--formula", double.name], host_arch)
    port = other.binary or os.path.join(other.prefix, "bin", "port")
    return typed([port, "uninstall", double.name] + ([double.version] if double.version else []), True)


def move_out(chosen: str, other: Instance) -> str:
    """Return the `plan` command of the move out of an installation, which rids it of its copies

    Where the installation's command cannot run, a plan uninstalls nothing one by one, so it names `--delete`.

    @param chosen  the options that name the installation that stays, as `doctor_report.keeps` gives them
    @param other   the installation the packages move out of
    @returns       the command
    """
    return f"brew-ports plan{chosen}" + ("" if other.drivable else f" --delete {shlex.quote(other.prefix)}")


def findings(doubles: Sequence[Double], target: Instance, instances: Sequence[Instance],
             host_arch: str) -> list[Issue]:
    """Return the findings about the packages of the other installations that the installation that stays has too

    @param doubles    those packages, as `find` gives them
    @param target     the installation that stays
    @param instances  the installations the scan found
    @param host_arch  the Mac's architecture, for the command that uninstalls one copy
    @returns          one finding per other installation that holds such packages: their names, why that
                      matters, the plan that rids the Mac of them, and the command for one that can go alone
    """
    by_prefix = doctor_report.known(instances)
    found: dict[str, list[Double]] = {}
    for double in doubles:
        found.setdefault(double.other.prefix, []).append(double)
    out = []
    for prefix, copies in found.items():
        other = by_prefix[prefix]
        names = [d.name if d.name == d.kept else f"{d.name} ({d.kept} in {at(target)})" for d in copies]
        does = ("uninstalls these copies, except those that a package staying there still needs" if other.drivable
                else f"deletes that installation whole afterwards, as its `{COMMAND_OF[other.manager]}` command "
                     "cannot run")
        notes = {"why": WHY, "plan": f"Fix: {move_out(doctor_report.keeps(target, by_prefix), other)} (plans the "
                                     f"move out of {at(other)}, which {does})"}
        free = next((d for d in copies if not d.reasons()), None)
        if free is not None:
            notes["one"] = (f"To uninstall one of them yourself once the copy you keep works, such as {free.name}: "
                            f"{uninstall(free, host_arch)}")
        title = (f"{counted(len(copies), 'package')} of {at(other)} {'is' if len(copies) == 1 else 'are'} "
                 f"installed in {at(target)} too")
        out.append(Issue(code=CODE, severity=Severity.HIGH, title=title, subject=None, instance_prefix=prefix,
                         evidence=[", ".join(names[i:i + NAMES_SHOWN]) for i in range(0, len(names), NAMES_SHOWN)],
                         remedies=[replace(doctor.note(CODE, prefix, text),
                                           action_id=doctor.remedy_id(CODE, prefix, step))
                                   for step, text in notes.items()],
                         auto_fix=False, confirm_each=False, repairs_install=False, blocks=()))
    return out

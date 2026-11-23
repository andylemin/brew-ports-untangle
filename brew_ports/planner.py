"""`brew-ports plan`: a scan becomes `plan.json`, or `plan-refused.json` with the reasons it is refused

Usage errors and the findings that block whatever the answers stop it before any terminal question.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import doctor, envclean, model, plan_phases, plan_report, plan_sets, progress, report, scan, state
from .context import Context
from .env import interpreters as env_interpreters
from .equiv import repology as repology_mod, resolver
from .homebrew import locate as brew_locate
from .macports import locate as mp_locate
from .model import Confidence, Instance, Issue, Manager, Mapping, Plan
from .plan_sets import DROPPED, KEPT, MIGRATED, UNMIGRATABLE, WITHDRAWN, Key, Root, SourceGraph, Unit
from .report import COMMAND_OF, at, manager_name, place, possessive, some, typed
from .runner import ActionFailed, BaseRunner, EscalationFailed, PreflightError, start_run

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_ACTION = 4

PLAN_FILE = "plan.json"
REFUSED_FILE = "plan-refused.json"
NO_RECORD = plan_sets.NO_RECORD
ONLY_DELETES_NOTHING = ("--only moves just the named packages, so no old installation is deleted. "
                        "Leave out --only or --delete")
# Where `--refresh` stands when a pass plans, and how a missing package list then ends its error.
BEFORE, DECLINED, UNASKED, DONE = "before", "declined", "unasked", "done"
NO_LIST = {
    None: ". Plan again with --refresh added, which fetches it first",
    DECLINED: ". Plan again and answer yes to the update that --refresh offers, which fetches it",
    UNASKED: ". --refresh asks before it fetches one, and there is no terminal to ask on: plan again with --yes added",
    DONE: ", although the update ran. `brew-ports doctor` shows what is wrong with it",
}
LANGUAGE_FILE = "language-%s.txt"
LANGUAGE_HELP = {
    "pip": "# Python packages: `pipx install <name>` for one that installs commands, `python3 -m venv` for a "
           "library; `pipx reinstall-all` rebuilds pipx venvs on a removed interpreter",
    "cpan": "# Perl modules: `cpanm <module>`",
    "gem": "# Ruby gems: `gem install <name>`",
    "npm": "# npm packages: `npm install -g <name>`",
}


def split_names(values: Sequence[str] | None) -> list[str]:
    """Split repeated comma lists: `--only a,b --only c` -> ['a', 'b', 'c']

    @param values  the values of a repeated option, each a comma list; None when the option is absent
    @returns       the names in order, stripped, without empty ones
    """
    out: list[str] = []
    for value in values or []:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def _flag(value: bool) -> str:
    """Return a flag as `Plan.options` text

    @param value  the flag's value
    @returns      `true` or `false`
    """
    return "true" if value else "false"


@dataclass
class PlanOptions:
    """The options of `brew-ports plan`"""

    target: Manager
    target_prefix: str | None = None
    only: list[str] = field(default_factory=list)
    keep: list[str] = field(default_factory=list)          # --leave
    drop: list[str] = field(default_factory=list)          # --uninstall
    maps: list[str] = field(default_factory=list)          # --replace: raw OLD=NEW values
    accept_medium: bool = False                            # --accept-closest
    yes: bool = False
    casks: str | None = None                            # keep, drop or map; None: the default keep, not given
    lang_packages: str = "report"                          # pipx with --pipx
    start_services: bool = False
    upgrade_all: bool = False                              # upgrade every outdated package of the target
    keep_managers: bool = False                            # uninstall no old installation
    delete: list[str] = field(default_factory=list)        # the old installations to delete whatever their state
    repology: bool = False
    refresh: bool = False
    out: str | None = None
    rescan: bool = False

    @classmethod
    def from_args(cls, args: Any) -> "PlanOptions":
        """Build the options from the `plan` subparser's namespace

        @param args  the parsed `plan` command line
        @returns     the options, with the comma lists of `--only`, `--leave`, `--uninstall` and `--delete` split
        """
        return cls(target=Manager(args.target), target_prefix=args.target_prefix, only=split_names(args.only),
                   keep=split_names(args.keep), drop=split_names(args.drop), maps=list(args.map or []),
                   accept_medium=args.accept_medium, yes=args.yes, casks=args.casks,
                   lang_packages=args.lang_packages, start_services=args.start_services,
                   upgrade_all=args.upgrade_all,
                   keep_managers=args.keep_managers, delete=split_names(args.delete), repology=args.repology,
                   refresh=args.refresh, out=args.out, rescan=args.rescan)

    @property
    def cask_policy(self) -> str:
        """Return `--casks`, or `keep` when it is not given

        @returns  `keep`, `drop` or `map`
        """
        return self.casks or "keep"

    def as_strings(self, target_prefix: str, removed: Sequence[str]) -> dict[str, str]:
        """Return the options as `Plan.options` text, with the target prefix and removed instances resolved

        @param target_prefix  the prefix of the chosen target
        @param removed        the prefixes of the old installations the plan uninstalls after the move
        @returns              each option's text by name: a flag `true` or `false`, a list joined with commas
        """
        return {"target": self.target.value, "target_prefix": target_prefix, "only": ",".join(self.only),
                "keep": ",".join(self.keep), "drop": ",".join(self.drop), "map": ",".join(self.maps),
                "accept_medium": _flag(self.accept_medium), "yes": _flag(self.yes), "casks": self.cask_policy,
                "casks_explicit": _flag(self.casks is not None), "lang_packages": self.lang_packages,
                "start_services": _flag(self.start_services), "upgrade_all": _flag(self.upgrade_all),
                "remove_manager": ",".join(removed),
                "keep_managers": _flag(self.keep_managers), "delete": ",".join(self.delete),
                "repology": _flag(self.repology), "refresh": _flag(self.refresh), "out": self.out or ""}


@dataclass
class PlanOutcome:
    """What `build` hands back: the exit code, the report lines and the file it wrote"""

    plan: Plan | None            # the plan, on exit 0 only
    exit_code: int
    report: list[str]            # the lines for standard output
    result_file: str | None      # "plan.json" or "plan-refused.json"
    path: str | None = None
    draft: Plan | None = None    # the refused plan, when one was built
    problems: list[str] = field(default_factory=list)   # why there is no plan: the lines for the error stream


class _Defaults:
    """The answers of `--yes`: every default"""

    tty = False
    yes = True

    @staticmethod
    def choose(_question: str, _options: Sequence[str], default: str) -> str:
        """Return the default answer of a question with options

        @param _question  the question, never shown
        @param _options   the answers it offers
        @param default    the answer taken
        @returns          `default`
        """
        return default

    @staticmethod
    def confirm(_question: str, default: bool = False) -> bool:
        """Return the default answer of a yes-or-no question

        @param _question  the question, never shown
        @param default    the answer taken
        @returns          `default`
        """
        return default

    @staticmethod
    def confirm_terminal(_question: str) -> bool:
        """Decline a question only a terminal answers, which `--yes` never does

        @param _question  the question, never shown
        @returns          False
        """
        return False


class _Stop(Exception):
    """The end of a pass: its exit code, the report lines that say why, and the findings that block it"""

    def __init__(self, code: int, lines: Sequence[str], blocking: Sequence[Issue] = ()) -> None:
        """Carry the exit code, the lines and the blocking findings to `_Composer.run`

        @param code      `EXIT_USAGE` or `EXIT_PREFLIGHT`
        @param lines     the report lines, joined as the exception's message
        @param blocking  the findings that block the plan
        """
        super().__init__("; ".join(lines))
        self.code = code
        self.lines = list(lines)
        self.blocking = list(blocking)


@dataclass
class Draft:
    """Everything `build` found, for the report and the two files"""

    exit_code: int = EXIT_OK
    target: Instance | None = None
    sources: list[Instance] = field(default_factory=list)
    roots: dict[Key, Root] = field(default_factory=dict)
    sets: plan_sets.Sets | None = None
    upgrades: plan_phases.Upgrades | None = None
    plan: Plan | None = None
    errors: list[str] = field(default_factory=list)         # usage and preflight failures, and a failed refresh
    refusals: list[str] = field(default_factory=list)       # why the plan is refused (exit 1)
    blocking: list[Issue] = field(default_factory=list)     # the findings that block it (exit 3)
    notes: list[str] = field(default_factory=list)
    todo: list[str] = field(default_factory=list)           # what the user has to do before `apply`
    unreadable: set[str] = field(default_factory=set)       # the old installations whose packages cannot be read
    language_files: dict[str, str] = field(default_factory=dict)
    stops: list[model.Service] = field(default_factory=list)  # owned services phase 5 stops
    removed: list[Instance] = field(default_factory=list)   # the old installations the plan uninstalls
    candidates: list[Instance] = field(default_factory=list)  # those it uninstalls if the move leaves them empty
    stays: dict[str, str] = field(default_factory=dict)     # prefix -> why an old installation is not uninstalled
    settled: bool = False                                   # the sets are computed, so `removed` and `stays` hold
    only: bool = False                                      # --only: a move of the named packages
    accept_closest: bool = False                            # --accept-closest
    start_services: bool = False                            # --start-services
    upgrade_all: bool = False                               # --upgrade-all
    pipx: bool = False                                      # --pipx
    nothing: list[str] = field(default_factory=list)        # why there is nothing to plan, which is no error
    installed: set[str] = field(default_factory=set)        # the names of the target's active packages
    units: dict[Key, Unit] = field(default_factory=dict)    # every source unit


# Composition -----------------------------------------------------------------------------------

def _migrated_mapping(root: Root) -> Mapping:
    """Return the accepted mapping of a root that `decide` migrated

    @param root  a migrated root
    @returns     its mapping
    """
    if root.mapping is None:
        raise ValueError(f"the migrated root {root.unit.label()} has no mapping")
    return root.mapping


def listed(bundle: scan.ScanBundle, target: Instance) -> bool:
    """Return whether the scan holds a package list of the target, in which replacements are looked up

    A Homebrew without one still has a catalogue, whose source is `none`.

    @param bundle  the scan
    @param target  the installation the packages move into
    @returns       True when it has a package list
    """
    if target.manager is Manager.BREW:
        catalogue = bundle.catalogue(target.prefix)
        return catalogue is not None and catalogue.source != "none"
    return bundle.portindex(target.prefix) is not None


def _has(found: Sequence[Instance], manager: str) -> str:
    """Return what follows "there is no <manager> at <path>": the installations of it that this Mac has

    @param found    its installations
    @param manager  `Homebrew` or `MacPorts`
    @returns        the rest of the sentence
    """
    if not found:
        return f": {manager} is not installed"
    return f": this Mac has {' and '.join(at(inst) for inst in found)}"


def _elsewhere(manager: str, usual: str, found: Sequence[Instance]) -> str:
    """Return the error of a move into a manager that this Mac has, but not at its usual place

    @param manager  `Homebrew` or `MacPorts`
    @param usual    its usual place on this Mac
    @param found    its installations, none of them at the usual place
    @returns        what was found, and how to name the installation the packages move into
    """
    names = " and ".join(place(i) for i in found)
    if len(found) == 1:
        return (f"this Mac has no {manager} at {usual}, only {names}. To move the packages into that one, plan with "
                f"--target-prefix {found[0].prefix}")
    return (f"this Mac has no {manager} at {usual}. It has {names}: say which one the packages move into with "
            "--target-prefix")


class _Composer:
    """One pass of `plan` over one scan"""

    def __init__(self, bundle: scan.ScanBundle, options: PlanOptions, runner: Any, *, ask: Any,
                 state_dir: state.StateDir | None, run_dir: state.RunDir | None, refresh: str | None = None) -> None:
        """Start a pass with an empty draft

        @param bundle     the scan
        @param options    the plan's options
        @param runner     runs the commands; it holds the host's architecture and environment
        @param ask        answers the terminal questions
        @param state_dir  the state directory, or None
        @param run_dir    the run directory, or None
        @param refresh    where `--refresh` stands: `BEFORE` its question, which a missing package list never
                          stops, `DECLINED`, `UNASKED` or `DONE`; None without the option
        """
        self.bundle = bundle
        self.result = bundle.result
        self.options = options
        self.manager = options.target
        self.runner = runner
        self.ask = ask
        self.state_dir = state_dir
        self.run_dir = run_dir
        self.refresh = refresh
        self.host_arch = runner.host_arch
        self.environ: dict[str, str] = dict(runner.environ)
        self.draft = Draft(only=bool(options.only), accept_closest=options.accept_medium,
                           start_services=options.start_services, pipx=options.lang_packages == "pipx",
                           upgrade_all=options.upgrade_all)
        self.sources: list[Instance] = []
        self.graphs: dict[str, SourceGraph] = {}
        self.maps: dict[str, str] = {}
        self.only: set[Key] | None = None
        self.keep: set[Key] = set()
        self.dropped: set[Key] = set()
        self.extra_kept: dict[Key, str] = {}
        self.issues: list[Issue] = []
        self.removed: list[Instance] = []          # the old installations the plan uninstalls after the move
        self.forced: list[Instance] = []           # those of them that --delete names
        self.refusals: list[str] = []              # the refusals that the sets do not find
        self.told = False                          # the first question carries the overview
        # Placeholders until compose() reaches the step that computes each; no earlier step reads them.
        self.ctx = resolver.Context(target=self.manager)
        self.ties = plan_sets.Ties((), {}, plan_sets.default_data_dirs)
        self.sets = plan_sets.Sets()

    @property
    def target(self) -> Instance:
        """Return the target instance that `choose_target` picked, which every later step plans against

        @returns  the target instance
        """
        if self.draft.target is None:
            raise RuntimeError("the plan's target is read before choose_target picks it")
        return self.draft.target

    def run(self) -> Draft:
        """Compose the draft; a stop records its exit code, its lines and the findings that block the plan

        @returns  the draft
        """
        try:
            self.compose()
        except _Stop as stop:
            self.draft.exit_code = stop.code
            (self.draft.nothing if stop.code == EXIT_OK else self.draft.errors).extend(stop.lines)
            self.draft.blocking.extend(stop.blocking)
        return self.draft

    def compose(self) -> None:
        """Run the planning steps in order, from the target choice to the phases

        @throws _Stop  a usage error, a preflight failure or a blocking finding ends the pass
        """
        try:
            self.maps = resolver.parse_maps(self.options.maps)
        except ValueError as exc:
            raise _Stop(EXIT_USAGE, [str(exc)]) from None
        self.check_out()
        self.choose_target()
        if not self.sources:
            raise _Stop(EXIT_OK, [f"This Mac has only {place(self.target)}: there is nothing to move."])
        self.make_graphs()
        self.check_names()
        self.ctx = self.make_context()
        self.choose_roots()
        self.resolve()
        self.check_drop()
        self.early_blocking()
        self.questions()
        self.collisions()
        self.compute_sets()
        self.final_blocking()
        self.finish()

    def check_out(self) -> None:
        """Refuse an `--out` that cannot hold a file, before any question is asked

        @throws _Stop  exit 2 when it names a folder, or a file in a folder that does not exist
        """
        out = self.options.out
        if not out:
            return
        path = os.path.abspath(os.path.expanduser(out))
        if os.path.isdir(path):
            raise _Stop(EXIT_USAGE, [f"--out {out}: that is a folder. Name the file the plan is saved as"])
        if not os.path.isdir(os.path.dirname(path)):
            raise _Stop(EXIT_USAGE, [f"--out {out}: the folder {os.path.dirname(path)} does not exist"])

    # Roles ----------------------------------------------------------------------------------

    def choose_target(self) -> None:
        """Pick the target instance, and every other instance as a source

        @throws _Stop  exit 3 with nothing to install into; 2 for a `--target-prefix` that cannot be the target
        """
        instances = self.result.instances
        prefix = self.options.target_prefix
        if self.options.target is Manager.BREW:
            target = brew_locate.choose_target(instances, self.host_arch, prefix, self.environ)
            if target is None:
                raise _Stop(EXIT_PREFLIGHT, [self.no_homebrew(prefix)])
        else:
            try:
                target = mp_locate.choose_target(instances, self.host_arch, prefix)
            except mp_locate.TargetRefused as exc:
                raise _Stop(EXIT_USAGE, [f"--target-prefix: {exc}"]) from None
            if target is None:
                ports = [i for i in instances if i.manager is Manager.PORTS]
                if prefix:
                    text = f"there is no MacPorts at {prefix}" + _has(ports, "MacPorts")
                elif ports:
                    text = _elsewhere("MacPorts", mp_locate.DEFAULT_PREFIX, ports)
                else:
                    text = "MacPorts is not installed. Run `brew-ports bootstrap-ports`, then plan again"
                raise _Stop(EXIT_PREFLIGHT, [text])
        self.draft.target = target
        self.draft.sources = [i for i in instances if i is not target and i.prefix != target.prefix]
        self.sources = self.draft.sources
        self.draft.installed = {p.name for p in self.result.packages if p.instance_prefix == target.prefix
                                and (p.kind != "port" or p.active)}

    def no_homebrew(self, prefix: str | None) -> str:
        """Return why no Homebrew can take the packages, with what this Mac has in its place

        @param prefix  the `--target-prefix` value, or None
        @returns       the error: where a working Homebrew was looked for, what was found, and what to do
        """
        brews = [i for i in self.result.instances if i.manager is Manager.BREW]
        default = brew_locate.ARM64_PREFIX if self.host_arch == "arm64" else brew_locate.USR_LOCAL
        if prefix:
            return f"there is no Homebrew at {prefix}" + _has(brews, "Homebrew")
        if not brews:
            return "Homebrew is not installed. Install it (https://brew.sh), then plan again"
        here = next((i for i in brews if i.prefix == default), None)
        if here is not None:
            return f"nothing can move into {place(here)} as it is. `brew-ports doctor` shows the fix"
        return _elsewhere("Homebrew", default, brews) + ", or install Homebrew at the usual place (https://brew.sh)"

    def make_graphs(self) -> None:
        """Build the dependency graph of each source, and record every source unit in the draft

        A Homebrew source follows a dependency's alias or old name through its own catalogue.
        """
        for inst in self.sources:
            catalogue = self.bundle.catalogue(inst.prefix) if inst.manager is Manager.BREW else None

            def canonical(name: str, kind: str, cat=catalogue) -> str | None:
                return cat.canonical(name, kind) if cat is not None and kind in ("formula", "cask") else None
            units = plan_sets.units_of(inst, self.result.packages)
            self.graphs[inst.prefix] = SourceGraph(inst, units, canonical)
            self.draft.units.update((u.key, u) for u in units)

    def named(self, name: str) -> list[Unit]:
        """Return the units of that name in every source, as `--leave`, `--only` and `--uninstall` match names

        @param name  a package name; a port's matches in any case
        @returns     the units, source by source
        """
        return [u for g in self.graphs.values() for u in g.named(name)]

    def instance_at(self, path: str) -> Instance | None:
        """Return the installation at the path a `--delete` value names

        @param path  a prefix, in any spelling
        @returns     the instance, or None when none is there
        """
        return brew_locate.find_by_path(self.result.instances, path)

    # Usage checks -----------------------------------------------------------------------------

    def check_names(self) -> None:
        """Check the names the options give against the sources, and refuse every mismatch at once

        @throws _Stop  exit 2, a line per mismatch
        """
        opts = self.options
        errors = []
        where = " or ".join(at(inst) for inst in self.sources) or "any old installation"
        for flag, names in (("--leave", opts.keep), ("--only", opts.only), ("--uninstall", opts.drop),
                            ("--replace", sorted(self.maps))):
            for name in names:
                if not self.named(name):
                    errors.append(f"{flag} {name}: no package named {name} is installed in {where}")
        for name in sorted(set(opts.keep) & set(opts.drop)):
            errors.append(f"{name} is named in both --leave and --uninstall")
        if opts.delete and opts.only:
            errors.append(ONLY_DELETES_NOTHING)
        if opts.casks is not None and self.manager is Manager.BREW:
            errors.append("--casks is for a move into MacPorts (--target ports). Into Homebrew, apps stay where they "
                          "are and the Homebrew they move into takes over their record")
        for value in opts.delete:
            inst = self.instance_at(value)
            marker = plan_phases.marker_missing(inst) if inst is not None else None
            if inst is None:
                errors.append(f"--delete {value}: there is no Homebrew or MacPorts there")
            elif inst.prefix == self.target.prefix:
                errors.append(f"--delete {value}: that is where the packages move to")
            elif marker:
                errors.append(f"--delete {value}: {marker}, and brew-ports deletes no folder that it cannot tell is a "
                              "manager's")
            elif inst not in self.forced:
                self.forced.append(inst)
        if errors:
            raise _Stop(EXIT_USAGE, errors)
        # A name matches a port in any case; the matcher looks a package up by its own spelling.
        self.maps = {unit.name: new for old, new in self.maps.items() for unit in self.named(old)}
        self.keep = {u.key for n in opts.keep for u in self.named(n)}
        self.only = {u.key for n in opts.only for u in self.named(n)} if opts.only else None
        self.draft.candidates = self.candidates()

    def candidates(self) -> list[Instance]:
        """Return the old installations the plan uninstalls if the move leaves them empty

        A full move takes every old installation that looks like its manager's, whose command runs and whose
        packages are known; `--delete` adds the ones it names, whatever their state. `--only` and
        `--keep-managers` take none by themselves.

        @returns  the installations, in scan order; the overview's `stays` gets the reason of each one left out
        """
        out = []
        self.draft.unreadable = {inst.prefix for inst in self.sources if envclean.unlistable(inst)}
        for inst in self.sources:
            marker = plan_phases.marker_missing(inst)
            if inst in self.forced:
                out.append(inst)
            elif self.options.only:
                continue
            elif self.options.keep_managers:
                self.draft.stays[inst.prefix] = "stays installed, as you asked (--keep-managers)"
            elif marker:
                self.draft.stays[inst.prefix] = f"stays installed: {marker}, and brew-ports deletes no such folder"
            elif not inst.inventory_known:
                self.draft.stays[inst.prefix] = ("stays installed: brew-ports cannot read its record of installed "
                                                 "packages (`brew-ports doctor` says why)")
            elif inst.prefix in self.draft.unreadable:
                self.draft.stays[inst.prefix] = ("stays installed: its Cellar or Caskroom folder cannot be read, so "
                                                 "brew-ports cannot tell that it will be empty")
            elif not inst.drivable:
                self.draft.stays[inst.prefix] = (
                    "stays installed, since nothing can be uninstalled from it (`brew-ports doctor` says why its "
                    f"command cannot run); `--delete {inst.prefix}` deletes it whole after the move")
            else:
                out.append(inst)
        return out

    def make_context(self) -> resolver.Context:
        """Return the resolver's view of the target: its catalogue or PortIndex, its packages and the options

        @returns       the resolver context
        @throws _Stop  exit 2 when a `--replace` entry names no usable target; exit 3 without a package list
        """
        brew = self.manager is Manager.BREW
        prefix = self.target.prefix
        downloads = self.run_dir.ensure("downloads") if self.run_dir is not None else None
        repology = None
        if self.options.repology and self.state_dir is not None:
            repology = repology_mod.Repology(self.runner, self.state_dir.path, downloads)
        ctx = resolver.Context(
            target=self.manager, catalogue=self.bundle.catalogue(prefix) if brew else None,
            portindex=None if brew else self.bundle.portindex(prefix),
            installed=[p for p in self.result.packages if p.instance_prefix == prefix],
            lang_packages=self.options.lang_packages, repology=repology, accept_medium=self.options.accept_medium,
            maps=self.maps, runner=self.runner if self.options.lang_packages == "pipx" else None,
            downloads=downloads,
            source_catalogues={inst.prefix: cat for inst, cat, _ in self.bundle.brew
                               if cat is not None and inst.prefix != prefix})
        if not listed(self.bundle, self.target) and self.refresh != BEFORE:
            raise _Stop(EXIT_PREFLIGHT, [f"this Mac has no package list for {at(self.target)}, so no replacement "
                                         f"can be looked up{NO_LIST[self.refresh]}"])
        errors = []
        for name in sorted(self.maps):
            for unit in self.named(name):
                error = resolver.map_error(unit.pkg, ctx)
                if error and error not in errors:
                    errors.append(error)
        if errors:
            raise _Stop(EXIT_USAGE, errors)
        return ctx

    # Roots and their resolution ------------------------------------------------------------------

    def choose_roots(self) -> None:
        """Find the roots of every source, with the ties that make a dependency one"""
        units = {prefix: list(g.units.values()) for prefix, g in self.graphs.items()}
        extras = plan_sets.extras_ties(self.result.interpreter_extras, units)
        self.ties = plan_sets.Ties(self.result.services, extras, plan_sets.default_data_dirs)
        for graph in self.graphs.values():
            for unit in graph.units.values():
                reason = self.root_reason(unit)
                if reason:
                    self.draft.roots[unit.key] = Root(unit, reason)

    def root_reason(self, unit: Unit) -> str | None:
        """Return why a unit is a root, by the rule `recommend` shares

        @param unit  a source unit
        @returns     the reason, or None when it is no root
        """
        return plan_sets.root_reason(unit, target=self.manager, cask_policy=self.options.cask_policy,
                                     only=self.only, ties=self.ties)

    def resolve(self) -> None:
        """Map each root to the target after choosing the plan's Python; a `--leave` root stays unmapped"""
        roots = [r.unit.pkg for r in self.draft.roots.values() if r.key not in self.keep]
        self.ctx.python_version = resolver.plan_python(roots, self.ctx)
        progress.step("matching packages")
        progress.counting("packages", len(roots))
        for key, root in sorted(self.draft.roots.items()):
            if key in self.keep:
                root.status = KEPT
            else:
                root.mapping = resolver.resolve(root.unit.pkg, self.ctx)
                progress.count()

    def check_drop(self) -> None:
        """Refuse a `--uninstall` name that is neither an unmigratable root nor a port with only inactive versions

        @throws _Stop  exit 2, a line per refused name that says why the option does not apply to it
        """
        errors = []
        for name in self.options.drop:
            hits, reasons = [], []
            for unit in self.named(name):
                root = self.draft.roots.get(unit.key)
                why = self.fixed(unit) or self.undroppable(unit, root)
                if why:
                    reasons.append(why)
                else:
                    hits.append(unit.key)
            if not hits:
                errors.append(f"--uninstall {name}: {reasons[0]}")
            self.dropped.update(hits)
        if errors:
            raise _Stop(EXIT_USAGE, errors)

    def undroppable(self, unit: Unit, root: Root | None) -> str | None:
        """Return why `--uninstall` does not apply to a package, or None when it does

        The option is for a package the user installed that gets no replacement, and for a port with only
        inactive versions.

        @param unit  a unit the option names
        @param root  the unit's root, or None when it is none
        @returns     the reason, as the usage error ends
        """
        name = unit.name
        if unit.inactive_only:
            return None
        if root is None:
            if self.only is not None and unit.key not in self.only:
                return f"{name} is not among the packages --only names"
            if unit.kind == "cask":
                return f"{name} is an app, and {plan_sets.KEPT_APP}"
            return f"{name} is a dependency: the move uninstalls it once nothing that stays needs it"
        if root.mapping is None:
            return f"{name} stays where it is, as --leave says"
        if resolver.accepted(root.mapping, self.ctx):
            return f"{name} has a replacement and moves. To leave it where it is, plan with `--leave {name}`"
        return None

    # Blocking findings -----------------------------------------------------------------------

    def early_blocking(self) -> None:
        """Stop on a target whose command cannot run and on the findings that block whatever the answers

        Those are the CRITICAL ones, `ANY`, the target's `TARGET` and the `REMOVE` of the installations `--delete`
        names. A finding that only stops the uninstall of an installation the move would empty keeps that
        installation, and the overview says why.

        @throws _Stop  exit 3, with the blocking findings
        """
        self.issues = list(doctor.detect_all(self.bundle, self.runner))
        target = self.target.prefix
        plain = doctor.blocking(self.issues, doctor.PlanContext(target_prefix=target))
        for inst in [i for i in self.draft.candidates if i not in self.forced]:
            context = doctor.PlanContext(target_prefix=target, remove_prefixes=(inst.prefix,))
            held = [issue for issue in doctor.blocking(self.issues, context) if issue not in plain]
            if held:
                self.draft.candidates.remove(inst)
                self.draft.stays[inst.prefix] = ("stays installed, because a problem stops its uninstall: "
                                                 f"{held[0].title}. `brew-ports doctor` shows what was found")
        context = doctor.PlanContext(target_prefix=target, remove_prefixes=tuple(i.prefix for i in self.forced))
        self.block(doctor.blocking(self.issues, context))

    def block(self, found: list[Issue]) -> None:
        """Stop when the target's command cannot run or a finding blocks the plan

        @param found   the findings that block the plan
        @throws _Stop  exit 3, a line per reason, with the findings
        """
        lines = []
        if not self.target.drivable:
            first = (self.target.usability_detail or "").strip().splitlines()[:1]
            detail = f" ({first[0].rstrip(':')})" if first else ""
            lines.append(f"nothing can move into {at(self.target)}: its `{COMMAND_OF[self.manager]}` command cannot "
                         f"run{detail}. `brew-ports doctor` shows the fix")
        lines += doctor.blocked_by_lines(found, self.result.instances)
        if lines:
            raise _Stop(EXIT_PREFLIGHT, lines, found)

    def final_blocking(self) -> None:
        """Run the blocking check again once the sets are known

        It adds `UNINSTALL` of the sources the removal set names and `CASKS` of those it removes casks from.

        @throws _Stop  exit 3, with the blocking findings and the refused plan in the draft
        """
        sets = self.sets
        casks = sorted(p for p, pairs in list(sets.removal.items()) + list(sets.path_removed.items())
                       if any(kind in ("cask", "cask-adopted") for kind, _ in pairs))
        context = doctor.PlanContext(target_prefix=self.target.prefix, uninstall_prefixes=tuple(sorted(sets.removal)),
                                     cask_prefixes=tuple(casks), remove_prefixes=tuple(i.prefix for i in self.removed))
        try:
            self.block(doctor.blocking(self.issues, context))
        except _Stop:
            self.draft.plan = self.plan([])
            raise

    # The terminal questions -----------------------------------------------------------------------

    def choose(self, question: str, options: Sequence[str], default: str) -> str:
        """Ask a question with options, the plan's overview above the first one asked

        @param question  the question
        @param options   the answers it accepts
        @param default   the answer under `--yes`, without a terminal, or for an empty reply
        @returns         the answer
        """
        if not self.told:
            self.told = True
            question = "\n".join(plan_report.overview(self.draft) + ["", question])
        return self.ask.choose(question, options, default)

    def questions(self) -> None:
        """Ask about the roots without an installed-on-request record, then settle each root's mapping"""
        roots = self.draft.roots
        for key, root in sorted(roots.items()):
            if root.reason == NO_RECORD and key not in self.keep and key not in self.dropped:
                if self.choose(plan_report.no_record_question(root.unit), ("yes", "no"), "yes") == "no":
                    del roots[key]
        self.write_language_files()
        for key, root in sorted(roots.items()):
            if root.status == KEPT or root.mapping is None:
                continue
            self.decide(root, root.mapping)

    def decide(self, root: Root, mapping: Mapping) -> None:
        """Migrate a root whose mapping is accepted; else drop it or leave it unmigratable, asking when free to

        @param root     a root the resolver mapped
        @param mapping  its mapping
        """
        ok = resolver.accepted(mapping, self.ctx)
        closest = (f"{mapping.target_kind} {mapping.target_name}" if mapping.confidence is Confidence.MEDIUM
                   and mapping.target_name and not resolver.is_language(mapping) else None)
        asked = False
        if not ok and closest and root.key not in self.dropped:
            asked = getattr(self.ask, "tty", False) and not getattr(self.ask, "yes", False)
            answer = self.choose(plan_report.medium_question(root.unit, mapping, self.target), ("yes", "no"), "no")
            ok = resolver.accepted(mapping, self.ctx, answer == "yes")
        if ok:
            root.status = MIGRATED
            return
        first = mapping.evidence[0] if mapping.evidence else (
            f"nothing of that name, or like it, is in {possessive(manager_name(self.target))} package list")
        if closest and asked:
            first = f"you declined its closest match, {closest}"
        elif closest:
            first = (f"its closest match, {closest}, needs your yes: plan on a terminal without --yes, or with "
                     f"--accept-closest or `--replace {root.unit.name}={mapping.target_name}`")
        unit = root.unit
        if root.key in self.dropped:
            root.status = DROPPED
            data = resolver.keeps_data(unit.pkg)
            detail = (f"its data in {data} will be deleted with it" if data
                      else f"its closest match would be {closest}" if closest else root.note or first)
            root.note = f"as you asked (--uninstall); {detail}"
            return
        root.note = root.note or first
        if resolver.keeps_data(unit.pkg) or self.fixed(unit):
            root.status = UNMIGRATABLE
        elif unit.kind == "cask" and self.manager is Manager.PORTS and not closest:
            root.status = DROPPED
            again = f"; to have it again, install it from {unit.pkg.homepage}" if unit.pkg.homepage else ""
            root.note = f"--casks replace uninstalls it: {root.note}{again}"
        else:
            question = plan_report.unmigratable_question(
                unit, root.note, self.target, emptied=unit.inst in self.draft.candidates,
                forced=unit.inst in self.forced, manual=unit.kind == "cask" and unit.pkg.privileged_uninstall)
            root.status = DROPPED if self.choose(question, ("keep", "drop"), "keep") == "drop" else UNMIGRATABLE

    def fixed(self, unit: Unit) -> str | None:
        """Return why the plan cannot uninstall a package whatever the user answers, or None when it can

        @param unit  a source unit
        @returns     the reason: its installation's command cannot run and `--delete` does not name it
        """
        inst = unit.inst
        if not inst.drivable and inst not in self.forced:
            return (f"nothing can be uninstalled from {at(inst)}, because its `{COMMAND_OF[inst.manager]}` command "
                    f"cannot run. `--delete {inst.prefix}` deletes it whole after the move")
        return None

    def write_language_files(self) -> None:
        """Write a requirements file per language, with the names tried as hints and the manual steps

        An unmigratable language root names its file as its reason.
        """
        groups: dict[str, list[tuple[Root, Mapping]]] = {}
        for _, root in sorted(self.draft.roots.items()):
            if root.mapping is not None and resolver.is_language(root.mapping):
                groups.setdefault(root.mapping.target_kind, []).append((root, root.mapping))
        for kind, roots in sorted(groups.items()):
            lines = [LANGUAGE_HELP.get(kind, f"# {kind} packages")]
            for root, mapping in roots:
                hints = resolver.language_hints(mapping) or [root.unit.name]
                lines.append(f"{hints[0]}  # from {root.unit.label()}")
                lines.extend(f"# also tried: {h}" for h in hints[1:])
            name = LANGUAGE_FILE % kind
            path = self.run_dir.write_json(name, "\n".join(lines) + "\n") if self.run_dir is not None else name
            self.draft.language_files[kind] = path
            for root, mapping in roots:
                if not resolver.accepted(mapping, self.ctx):
                    language = plan_report.LANGUAGE_NAMES.get(kind, kind)
                    reason = (f"it is a {language} package, which the plan does not move: "
                              f"{report.tilde(path)} lists what to reinstall")
                    root.note = reason
                    mapping.evidence.insert(0, reason)

    # The sets -------------------------------------------------------------------------------------

    def collisions(self) -> None:
        """Keep each mapped source port whose files outside its prefix the target port would install too"""
        if self.manager is not Manager.PORTS:
            return
        for _, root in sorted(self.draft.roots.items()):
            unit = root.unit
            if root.status != MIGRATED or unit.kind != "port" or _migrated_mapping(root).target_kind != "port":
                continue
            inv = self.bundle.macports(unit.prefix)
            files = [f.location for row in unit.rows if row.active for f in (inv.files(row) if inv else [])
                     if f.active]
            hits = plan_sets.colliding_files(unit.inst, self.target, files)
            if hits:
                self.withdraw(root, f"its replacement in {at(self.target)} would overwrite its files outside "
                              f"{unit.prefix} ({', '.join(hits[:3])})")

    def withdraw(self, root: Root, reason: str) -> None:
        """Keep a root for its own sake: no install, and its mapping listed as unmigratable

        @param root    a migrated or dropped root
        @param reason  why it stays, for the report and the kept set
        """
        if root.status == MIGRATED:
            root.status = WITHDRAWN
            _migrated_mapping(root).evidence.insert(0, f"kept: {reason}")
        elif root.status == DROPPED:
            root.status = UNMIGRATABLE
        root.note = reason
        self.extra_kept[root.key] = reason
        self.dropped.discard(root.key)

    def inputs(self) -> plan_sets.Inputs:
        """Return what `plan_sets.compute` needs from the draft

        @returns  the inputs of the sets
        """
        roots = self.draft.roots
        dropped = {k for k, r in roots.items() if r.status == DROPPED}
        dropped |= {k for k in self.dropped if (unit := self.unit(k)) is not None and unit.inactive_only}
        root_owned: set[Key] = set()
        for inst, _, inv in self.bundle.brew:
            if inst.prefix in self.graphs:
                root_owned |= {(inst.prefix, "formula", name) for name in inv.root_owned}
        return plan_sets.Inputs(graphs=self.graphs, target=self.manager, roots=roots, keep=set(self.keep),
                                dropped=dropped, named=set(self.dropped), root_owned=root_owned, ties=self.ties,
                                policy=self.options.cask_policy, only=self.only,
                                remove={i.prefix for i in self.removed}, forced={i.prefix for i in self.forced},
                                extra_kept=dict(self.extra_kept))

    def unit(self, key: Key) -> Unit | None:
        """Return the source unit of a key

        @param key  the unit's `(prefix, kind, name key)`
        @returns    the unit, or None when no source has it
        """
        graph = self.graphs.get(key[0])
        return graph.units.get(key) if graph else None

    def loose_shell(self) -> tuple[str, str] | None:
        """Return the login shell and its installation's prefix when no package of that old installation owns it

        @returns  `(shell, prefix)`, or None when the shell lies elsewhere or belongs to a package
        """
        environment = self.result.environment
        shell, prefix = environment.get("login_shell"), environment.get("login_shell_prefix")
        graph = self.graphs.get(prefix or "")
        if not shell or not prefix or graph is None:
            return None
        owner = plan_sets.package_at(graph, shell, environment.get("login_shell_realpath"), self.bundle.owner_of)
        return None if owner is not None else (shell, prefix)

    def compute_sets(self) -> None:
        """Compute the package sets, then settle which old installations the plan uninstalls

        The sets are computed again after withdrawing a root that provides the login shell, and once more when
        an installation that the move was to empty keeps something.
        """
        self.removed = list(self.draft.candidates)
        self.sets = plan_sets.compute(self.inputs())
        found = plan_sets.login_shell_key(self.result.environment, self.graphs, self.sets,
                                          owner_of=self.bundle.owner_of)
        if found is not None:
            key, base = found
            root = self.draft.roots.get(key)
            mapping = root.mapping if root is not None and root.status == MIGRATED else None
            executables = self.ctx.catalogue.executables if self.ctx.catalogue is not None else (lambda name: [])
            if not plan_sets.installs_basename(mapping, base, self.manager, executables):
                shell = self.result.environment.get("login_shell")
                lacks = (f"its replacement, {mapping.target_name}, is not known to provide `{base}`"
                         if mapping is not None else f"the plan installs no replacement that provides `{base}`")
                reason = (f"it is your login shell ({shell}), and {lacks}; change your shell first "
                          "(`chsh -s /bin/zsh`) to move it")
                if root is not None:
                    self.withdraw(root, reason)
                else:
                    self.extra_kept[key] = reason
                self.sets = plan_sets.compute(self.inputs())
        self.settle()
        self.draft.sets = self.sets

    def settle(self) -> None:
        """Keep each old installation that the move does not leave empty, and say why in the overview

        An installation `--delete` names is never kept here: the plan is refused when it holds something. A login
        shell that lies in an installation and belongs to no package of it holds it too.
        """
        shell = self.loose_shell()
        for inst in list(self.removed):
            why = self.sets.holds(inst.prefix, self.draft.units, command=False)
            if not why and shell is not None and shell[1] == inst.prefix:
                why = (f"your login shell ({shell[0]}) is inside it and belongs to no package: change your shell "
                       "first (`chsh -s /bin/zsh`), then plan again")
                if inst in self.forced:
                    self.refusals.append(f"--delete {inst.prefix}: {at(inst)} cannot be deleted while {why}")
            if why and inst in self.forced:
                self.draft.stays[inst.prefix] = f"stays installed although --delete names it: {why}"
            elif why:
                self.removed.remove(inst)
                self.draft.stays[inst.prefix] = f"stays installed, because {why}"
        if len(self.removed) != len(self.draft.candidates):
            self.sets = plan_sets.compute(self.inputs())
        self.draft.removed = self.removed
        self.draft.settled = True

    # Phases, upgrades and refusals ------------------------------------------------------------------

    def accepted(self) -> list[Mapping]:
        """Return the accepted mappings in plan order: by source and kind, each after the roots it needs

        @returns  the mappings of the migrated roots
        """
        out: list[Mapping] = []
        for prefix, graph in sorted(self.graphs.items()):
            keys = sorted((k for k, r in self.draft.roots.items() if k[0] == prefix and r.status == MIGRATED),
                          key=self.order)
            out.extend(_migrated_mapping(self.draft.roots[k]) for k in graph.dependency_order(keys))
        return out

    @staticmethod
    def target_roots(mappings: Sequence[Mapping]) -> dict[str, list[str]]:
        """Return each target package and companion of the mappings, with the roots that need it

        @param mappings  the accepted mappings
        @returns         the source names of the roots, by target package name
        """
        targets: dict[str, list[str]] = {}
        for m in mappings:
            if m.target_kind in ("formula", "port") and m.target_name:
                targets.setdefault(m.target_name, []).append(m.source.name)
            for companion in m.companions:
                targets.setdefault(companion, []).append(m.source.name)
        return targets

    def rebuilds(self) -> list[str]:
        """Return the target packages linked into what the plan removes, and note the links that remain

        @returns  the names of the target packages to rebuild
        """
        removed = {prefix: {(("cask" if k == "cask-adopted" else k), plan_sets.name_key(k, n)) for k, n in pairs}
                   for prefix, pairs in list(self.sets.removal.items()) + list(self.sets.path_removed.items())}
        racks = {prefix: self.bundle.formula_racks(prefix) for prefix in removed}
        rebuild, remaining = plan_phases.cross_prefix_rebuilds(self.result.linkage, self.target, self.result.instances,
                                                               removed=removed, racks=racks,
                                                               gone={i.prefix for i in self.removed},
                                                               owner_of=self.bundle.owner_of)
        self.draft.notes += remaining
        return rebuild

    def outdated(self, casks: bool = False) -> dict[str, str]:
        """Return the target's outdated formulae, or casks, with the versions `brew outdated` names

        @param casks  return the casks, not the formulae
        @returns      the version each one upgrades to, by name; empty for a MacPorts target
        """
        for inst, _, inv in self.bundle.brew:
            if inst.prefix == self.target.prefix:
                return dict(inv.outdated_casks if casks else inv.outdated_formulae)
        return {}

    def finish(self) -> None:
        """Fix the plan's repairs, rebuilds, upgrades and phases, and the refusals they add"""
        view = plan_phases.TargetView(self.target, self.ctx.installed, self.ctx.catalogue, self.ctx.portindex)
        mappings = self.accepted()
        targets = self.target_roots(mappings)
        repairs = plan_phases.phase2_issues(self.issues, view, set(view.closure(targets)))
        repaired = [i.subject for i in repairs if i.code in plan_phases.REINSTALL_CODES and i.subject]
        rebuild = [n for n in self.rebuilds() if view.key(n) not in {view.key(r) for r in repaired}]
        ups = plan_phases.upgrades(view, targets, repaired + rebuild, self.outdated())
        if self.options.upgrade_all:
            plan_phases.every_upgrade(view, self.host_arch, ups, self.outdated(), self.outdated(casks=True))
        self.draft.upgrades = ups
        refusals = list(self.sets.refusals) + self.refusals
        for name, roots in sorted(ups.pinned.items()):
            needed = (f"the replacement{'' if len(roots) == 1 else 's'} of {some(roots)}" if roots
                      else "the replacements")
            leave = f", or plan with `--leave {','.join(roots)}`" if roots else ""
            unpin = typed([self.target.binary or "brew", "unpin", name])
            refusals.append(f"installing {needed} would upgrade {name} ({ups.reasons.get(name)}), which you pinned. "
                            f"Run `{unpin}`{leave}")
        items, projects = plan_phases.installs(mappings)
        if self.manager is Manager.BREW:
            phase3 = plan_phases.phase3_brew(view, self.host_arch, items, projects=projects, explicit=ups.explicit,
                                             rebuilds=rebuild, casks=list(ups.casks))
        else:
            homebrew = any(i.manager is Manager.BREW for i in self.result.instances)
            phase3 = plan_phases.phase3_ports(view, self.host_arch, items, projects=projects, homebrew_present=homebrew,
                                              rebuilds=rebuild, others=ups.others)
        survivors = [i for i in self.result.instances if i not in self.removed]
        phase6 = plan_phases.phase6(self.removed, self.target, self.result.services, self.environ, survivors)
        phases = plan_phases.assemble(plan_phases.phase2(repairs), phase3, phase6, bool(self.removed))
        self.draft.stops = self.stops()
        self.draft.todo += self.user_jobs()
        self.draft.notes += self.sets.notes
        self.draft.plan = self.plan(phases)
        if refusals:
            self.draft.refusals = refusals
            self.draft.exit_code = EXIT_REFUSED

    def stops(self) -> list[model.Service]:
        """Return the owned services phase 5 will stop: those whose package is a pair of the removal set

        A `cask-adopted` pair stops nothing.

        @returns  the services
        """
        pairs = {(prefix, kind, plan_sets.name_key(kind, name)) for prefix, ps in self.sets.removal.items()
                 for kind, name in ps if kind != "cask-adopted"}
        return [s for s in self.result.services if s.owned and s.package and s.package_kind
                and (s.instance_prefix, s.package_kind, plan_sets.name_key(s.package_kind, s.package)) in pairs]

    def user_jobs(self) -> list[str]:
        """Return a report line for each user launchd job that runs a binary the plan removes

        @returns  the lines
        """
        removed = self.sets.removed_keys()
        gone = {i.prefix for i in self.removed}
        out = []
        for svc in self.result.services:
            graph = self.graphs.get(svc.instance_prefix)
            if svc.owned or graph is None:
                continue
            unit = plan_sets.package_at(graph, svc.program, None, self.bundle.owner_of) if svc.program else None
            if svc.instance_prefix in gone or (unit is not None and unit.key in removed):
                program = svc.program or f"a program in {svc.instance_prefix}"
                wait = " `apply` stops before it deletes the installation while the service runs." if (
                    svc.instance_prefix in gone) else ""
                out.append(f"Your own service {report.tilde(svc.plist)} runs {program}, which this plan uninstalls. "
                           f"Point it at the replacement, or delete it.{wait}")
        return out

    def packages(self, keys: Iterable[Key]) -> list[model.Package]:
        """Return the representative package of each unit, in plan order

        @param keys  the units' keys
        @returns     the packages of the keys a source has
        """
        units = [self.unit(k) for k in sorted(keys, key=self.order)]
        return [u.pkg for u in units if u is not None]

    def plan(self, phases: list[model.Phase]) -> Plan:
        """Return the `Plan` of the draft with these phases

        @param phases  the phases; empty for a plan the final blocking check refuses
        @returns       the plan
        """
        roots = self.draft.roots
        sets = self.sets
        upgrades = list(self.draft.upgrades.names) if self.draft.upgrades else []
        return Plan(
            created=state.now_iso(), run_id=self.run_dir.run_id if self.run_dir is not None else "",
            target=self.manager, instances=list(self.result.instances),
            source_prefixes=[s.prefix for s in self.sources], target_prefix=self.target.prefix,
            roots=self.packages(roots), kept=self.packages(sets.kept),
            left_in_place=[u.pkg for u in sets.left_in_place], mappings=self.accepted(),
            unmigratable=[r.mapping for _, r in sorted(roots.items(), key=lambda kv: self.order(kv[0]))
                          if r.mapping is not None and r.status in (UNMIGRATABLE, DROPPED, WITHDRAWN)],
            removal_set=dict(sets.removal), path_removed=dict(sets.path_removed),
            manual_casks=[u.name for u in sets.manual_casks], target_upgrades=upgrades, phases=phases,
            options=self.options.as_strings(self.target.prefix, [i.prefix for i in self.removed]))

    @staticmethod
    def order(key: Key) -> tuple[str, int, str]:
        """Return the sort key of plan order: by source, then kind, then name in any case

        @param key  a unit's key
        @returns    the prefix, the kind's rank in `KIND_ORDER` and the lower-case name
        """
        return (key[0], plan_sets.KIND_ORDER.get(key[1], 9), key[2].lower())


# Files and the outcome --------------------------------------------------------------------------

def _finish(draft: Draft, options: PlanOptions, run_dir: state.RunDir | None, head: Sequence[str],
            verbose: bool = False, *, updated: str | None = None, after: Sequence[str] = ()) -> PlanOutcome:
    """Write `plan.json`, or `plan-refused.json` with the reasons, and build the outcome

    A plan is also copied to `--out`; the reasons of a plan that was not made never replace that file.

    @param draft    the pass's draft
    @param options  the plan's options
    @param run_dir  the run directory the file goes into; None writes nothing
    @param head     the report lines that come before the draft's
    @param verbose  whether the report holds every replacement's reasons and the whole lists
    @param updated  the installation whose package list `--refresh` updated, as the report names it; its head
                    line is printed even when no plan follows
    @param after    the lines that follow the reasons of a plan that was not made
    @returns        the outcome
    """
    if draft.nothing:
        return PlanOutcome(plan=None, exit_code=EXIT_OK, report=list(draft.nothing), result_file=None)
    lines = plan_report.render(draft, verbose)
    if lines and head:
        lines = list(head) + [""] + lines
    elif updated:
        lines = list(head)
    problems = plan_report.problems(draft)
    if problems:
        problems += list(after)
    exit_code = draft.exit_code
    ok = exit_code == EXIT_OK and draft.plan is not None
    name = PLAN_FILE if ok else REFUSED_FILE
    if ok:
        text = model.to_json(draft.plan)
    else:
        text = json.dumps({"refused": {"exit": exit_code, "reasons": draft.errors + draft.refusals,
                                       "blocking": model.to_plain(draft.blocking)},
                           "plan": model.to_plain(draft.plan) if draft.plan is not None else None,
                           "report": lines + problems}, indent=2, sort_keys=True)
    path = run_dir.write_json(name, text) if run_dir is not None else None
    if path is not None and run_dir is not None and ok:
        out = options.out
        try:
            if out:
                shutil.copyfile(path, os.path.abspath(os.path.expanduser(out)))
        except OSError as exc:
            problems.append(f"brew-ports: the plan could not be copied to {out}: {exc.strerror or exc}. It is saved in "
                            "the run folder")
            exit_code, out = EXIT_ACTION, None
        lines += plan_report.closing(path, out, run_dir.path, updated)
    elif path is not None and exit_code not in (EXIT_USAGE, EXIT_ACTION):
        problems += plan_report.refused_closing(path)
    return PlanOutcome(plan=draft.plan if ok else None, exit_code=exit_code, report=lines,
                       result_file=name if path is not None else None, path=path,
                       draft=None if ok else draft.plan, problems=problems)


def _refreshed(bundle: scan.ScanBundle, options: PlanOptions, runner: Any, *, ask: Any,
               state_dir: state.StateDir | None, run_dir: state.RunDir | None, verbose: bool = False) -> PlanOutcome:
    """Update the target's package list, then plan over a fresh scan

    A first pass with the default answers must find nothing that stops the plan before anything runs.

    @param bundle     the scan
    @param options    the plan's options
    @param runner     runs the update and the fresh scan; it holds the host's architecture and environment
    @param ask        answers the terminal questions, the update's among them
    @param state_dir  the state directory, or None
    @param run_dir    the run directory, or None
    @param verbose    whether the report holds every replacement's reasons and the whole lists
    @returns          the outcome
    """
    first = _Composer(bundle, options, runner, ask=_Defaults(), state_dir=state_dir, run_dir=run_dir,
                      refresh=BEFORE).run()
    if first.exit_code in (EXIT_USAGE, EXIT_PREFLIGHT) or first.target is None or first.nothing:
        return _finish(first, options, run_dir, [], verbose,
                       after=["The package list was not updated (--refresh): the above comes first"])
    actions = plan_phases.refresh_actions(first.target, runner.host_arch)
    commands = "; ".join(doctor.describe(a) for a in actions)
    where = at(first.target)
    declined = ("the plan uses the list as it is" if listed(bundle, first.target)
                else "no plan is made, as this Mac has no package list of it yet")
    if not ask.confirm(f"`{commands}` updates the package list of {where}. If you answer no, {declined}.\n"
                       "Run it before planning?", default=False):
        asked = bool(getattr(ask, "tty", False))
        draft = _Composer(bundle, options, runner, ask=ask, state_dir=state_dir, run_dir=run_dir,
                          refresh=DECLINED if asked else UNASKED).run()
        why = (", as you answered" if asked else
               ": --refresh asks first, and there is no terminal to ask on (add --yes to run it)")
        return _finish(draft, options, run_dir, [f"The package list of {where} was not updated{why}; planned with it "
                                                 "as it is."], verbose)
    try:
        if any(a.sudo for a in actions):
            runner.sudo_preflight()
    except PreflightError as exc:
        return _finish(Draft(exit_code=EXIT_PREFLIGHT, target=first.target, errors=[str(exc)]), options, run_dir, [],
                       verbose)
    if state_dir is not None and run_dir is not None:
        state_dir.touch_dirty(run_dir.run_id, "plan --refresh")
    try:
        for action in actions:
            runner.run(action)
    except (ActionFailed, EscalationFailed) as exc:
        error = f"{exc}. Nothing was planned. Fix that, or plan without --refresh"
        return _finish(Draft(exit_code=EXIT_ACTION, target=first.target, errors=[error]), options, run_dir, [], verbose)
    fresh = scan.build(runner, runner.environ)
    try:
        if run_dir is not None:
            scan.write(fresh, run_dir)
        draft = _Composer(fresh, options, runner, ask=ask, state_dir=state_dir, run_dir=run_dir, refresh=DONE).run()
    finally:
        fresh.close()
    return _finish(draft, options, run_dir, [f"Updated the package list of {where} (`{commands}`)."], verbose,
                   updated=where)


def build(bundle: scan.ScanBundle, options: PlanOptions, runner: Any, *, ask: Any,
          state_dir: state.StateDir | None, run_dir: state.RunDir | None, verbose: bool = False) -> PlanOutcome:
    """Plan `bundle` under `options`, with the report lines and the file written into `run_dir`

    @param bundle     the scan
    @param options    the plan's options
    @param runner     runs the commands; it holds the host's architecture and environment
    @param ask        answers the terminal questions
    @param state_dir  the state directory, or None
    @param run_dir    the run directory, or None
    @param verbose    whether the report holds every replacement's reasons and the whole lists
    @returns          the outcome
    """
    if options.refresh:
        return _refreshed(bundle, options, runner, ask=ask, state_dir=state_dir, run_dir=run_dir, verbose=verbose)
    draft = _Composer(bundle, options, runner, ask=ask, state_dir=state_dir, run_dir=run_dir).run()
    return _finish(draft, options, run_dir, [], verbose)


def cmd_plan(ctx: Context, make_runner: Callable[[Context, state.RunDir], BaseRunner] | None = None) -> int:
    """Run `brew-ports plan` and print its report

    A scan younger than ten minutes is reused when no mutating command ran since; `--rescan` takes a fresh one.

    @param ctx          the command's context
    @param make_runner  builds the runner from the context and the run directory; None for `command_runner`
    @returns            the exit code
    """
    options = PlanOptions.from_args(ctx.args)
    run_dir, runner = start_run(ctx, 0, make_runner)
    with runner.signals():
        bundle, reused = scan.obtain(ctx.state, run_dir, runner, ctx.environ, rescan=options.rescan)
        try:
            if reused:
                env_interpreters.write_requirements(run_dir.path, bundle.result.interpreter_extras)
                ctx.console.info(report.SCAN_REUSED)
            outcome = build(bundle, options, runner, ask=ctx, state_dir=ctx.state, run_dir=run_dir,
                            verbose=ctx.console.verbose)
        finally:
            bundle.close()
    for line in outcome.report:
        ctx.console.out(line)
    for line in outcome.problems:
        ctx.console.warn(line)
    return outcome.exit_code

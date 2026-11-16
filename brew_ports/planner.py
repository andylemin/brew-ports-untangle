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

from . import doctor, model, plan_phases, plan_report, plan_sets, scan, state
from .context import Context
from .env import interpreters as env_interpreters
from .equiv import repology as repology_mod, resolver
from .homebrew import locate as brew_locate
from .macports import locate as mp_locate
from .model import Confidence, Instance, Issue, Manager, Mapping, Plan
from .plan_sets import DROPPED, KEPT, MIGRATED, UNMIGRATABLE, WITHDRAWN, Key, Root, SourceGraph, Unit
from .runner import ActionFailed, BaseRunner, EscalationFailed, PreflightError, start_run

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_ACTION = 4

PLAN_FILE = "plan.json"
REFUSED_FILE = "plan-refused.json"
NO_RECORD = plan_sets.NO_RECORD
LANGUAGE_FILE = "language-%s.txt"
LANGUAGE_HELP = {
    "pip": "# Python packages: `pipx install <name>` for one that installs commands, `python3 -m venv` for a "
           "library; `pipx reinstall-all` rebuilds pipx venvs on a removed interpreter",
    "cpan": "# Perl modules: `cpanm <module>`",
    "gem": "# Ruby gems: `gem install <name>`",
    "npm": "# npm packages: `npm install -g <name>`",
}


def _names(values: Sequence[str] | None) -> list[str]:
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
    keep: list[str] = field(default_factory=list)
    drop: list[str] = field(default_factory=list)
    maps: list[str] = field(default_factory=list)          # raw SOURCE=TARGET values
    accept_medium: bool = False
    yes: bool = False
    casks: str | None = None                            # None: the default keep, not given explicitly
    lang_packages: str = "report"
    start_services: bool = False
    remove_manager: list[str] | None = None             # None: absent; []: every source instance
    repology: bool = False
    refresh: bool = False
    dry_run: bool = False
    out: str | None = None
    rescan: bool = False

    @classmethod
    def from_args(cls, args: Any) -> "PlanOptions":
        """Build the options from the `plan` subparser's namespace

        @param args  the parsed `plan` command line
        @returns     the options, with the comma lists of `--only`, `--keep`, `--drop` and `--remove-manager` split
        """
        remove = None if args.remove_manager is None else _names([args.remove_manager])
        return cls(target=Manager(args.target), target_prefix=args.target_prefix, only=_names(args.only),
                   keep=_names(args.keep), drop=_names(args.drop), maps=list(args.map or []),
                   accept_medium=args.accept_medium, yes=args.yes, casks=args.casks,
                   lang_packages=args.lang_packages, start_services=args.start_services, remove_manager=remove,
                   repology=args.repology, refresh=args.refresh, dry_run=args.dry_run, out=args.out,
                   rescan=args.rescan)

    @property
    def cask_policy(self) -> str:
        """Return `--casks`, or `keep` when it is not given

        @returns  `keep`, `drop` or `map`
        """
        return self.casks or "keep"

    def as_strings(self, target_prefix: str, removed: Sequence[str]) -> dict[str, str]:
        """Return the options as `Plan.options` text, with the target prefix and removed instances resolved

        @param target_prefix  the prefix of the chosen target
        @param removed        the prefixes of the instances `--remove-manager` names
        @returns              each option's text by name: a flag `true` or `false`, a list joined with commas
        """
        return {"target": self.target.value, "target_prefix": target_prefix, "only": ",".join(self.only),
                "keep": ",".join(self.keep), "drop": ",".join(self.drop), "map": ",".join(self.maps),
                "accept_medium": _flag(self.accept_medium), "yes": _flag(self.yes), "casks": self.cask_policy,
                "casks_explicit": _flag(self.casks is not None), "lang_packages": self.lang_packages,
                "start_services": _flag(self.start_services), "remove_manager": ",".join(removed),
                "repology": _flag(self.repology), "refresh": _flag(self.refresh), "dry_run": _flag(self.dry_run),
                "out": self.out or ""}


@dataclass
class PlanOutcome:
    """What `build` hands back: the exit code, the report lines and the file it wrote"""

    plan: Plan | None            # the plan, on exit 0 only
    exit_code: int
    report: list[str]
    result_file: str | None      # "plan.json" or "plan-refused.json"
    path: str | None = None
    draft: Plan | None = None    # the refused plan, when one was built


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
    language_files: dict[str, str] = field(default_factory=dict)
    stops: list[model.Service] = field(default_factory=list)  # owned services phase 5 stops
    removed: list[Instance] = field(default_factory=list)   # instances --remove-manager names
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


class _Composer:
    """One pass of `plan` over one scan"""

    def __init__(self, bundle: scan.ScanBundle, options: PlanOptions, runner: Any, *, ask: Any,
                 state_dir: state.StateDir | None, run_dir: state.RunDir | None) -> None:
        """Start a pass with an empty draft

        @param bundle     the scan
        @param options    the plan's options
        @param runner     runs the commands; it holds the host's architecture and environment
        @param ask        answers the terminal questions
        @param state_dir  the state directory, or None
        @param run_dir    the run directory, or None
        """
        self.bundle = bundle
        self.result = bundle.result
        self.options = options
        self.manager = options.target
        self.runner = runner
        self.ask = ask
        self.state_dir = state_dir
        self.run_dir = run_dir
        self.host_arch = runner.host_arch
        self.environ: dict[str, str] = dict(runner.environ)
        self.draft = Draft()
        self.sources: list[Instance] = []
        self.graphs: dict[str, SourceGraph] = {}
        self.maps: dict[str, str] = {}
        self.only: set[Key] | None = None
        self.keep: set[Key] = set()
        self.dropped: set[Key] = set()
        self.extra_kept: dict[Key, str] = {}
        self.issues: list[Issue] = []
        self.removed: list[Instance] = []          # the instances --remove-manager names
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
            self.draft.errors.extend(stop.lines)
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
        self.choose_target()
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
                where = f" at {prefix}" if prefix else ""
                raise _Stop(EXIT_PREFLIGHT, [
                    f"no Homebrew instance to install into{where}: install Homebrew (the .pkg of "
                    "https://github.com/Homebrew/brew/releases, or the instructions at https://brew.sh), "
                    "then plan again"])
        else:
            try:
                target = mp_locate.choose_target(instances, self.host_arch, prefix)
            except mp_locate.TargetRefused as exc:
                raise _Stop(EXIT_USAGE, [f"--target-prefix: {exc}"]) from None
            if target is None:
                ports = [i for i in instances if i.manager is Manager.PORTS]
                if prefix:
                    text = f"no MacPorts instance at {prefix}"
                elif ports:
                    text = ("several MacPorts instances and none at /opt/local: name the target with "
                            "--target-prefix")
                else:
                    text = "MacPorts is not installed: run `brew-ports bootstrap-ports`, then plan again"
                raise _Stop(EXIT_PREFLIGHT, [text])
        self.draft.target = target
        self.draft.sources = [i for i in instances if i is not target and i.prefix != target.prefix]
        self.sources = self.draft.sources

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
        """Return the units of that name in every source, as `--keep`, `--only` and `--drop` match names

        @param name  a package name; a port's matches in any case
        @returns     the units, source by source
        """
        return [u for g in self.graphs.values() for u in g.named(name)]

    def instance_at(self, path: str) -> Instance | None:
        """Return the instance whose prefix a `--remove-manager` value names

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
        for flag, names in (("--keep", opts.keep), ("--only", opts.only), ("--drop", opts.drop),
                            ("--map", sorted(self.maps))):
            for name in names:
                if not self.named(name):
                    errors.append(f"{flag} {name}: no source instance has {name} installed")
        for name in sorted(set(opts.keep) & set(opts.drop)):
            errors.append(f"{name} is named in both --keep and --drop")
        if opts.remove_manager is not None:
            if opts.only:
                errors.append("--remove-manager cannot be combined with --only")
            if not opts.remove_manager:
                self.removed = list(self.sources)
            for value in opts.remove_manager:
                inst = self.instance_at(value)
                if inst is None:
                    errors.append(f"--remove-manager {value}: no Homebrew or MacPorts instance there")
                elif inst.prefix == self.target.prefix:
                    errors.append(f"--remove-manager {value}: that is the target")
                elif inst not in self.removed:
                    self.removed.append(inst)
            for inst in self.removed:
                if (inst.manager is Manager.BREW and self.manager is Manager.PORTS
                        and opts.casks not in ("drop", "map")):
                    errors.append(f"--remove-manager {inst.prefix}: a Homebrew source of a MacPorts target needs "
                                  "--casks drop or --casks map, because the default keep leaves Homebrew installed "
                                  "for its casks")
        if errors:
            raise _Stop(EXIT_USAGE, errors)
        self.draft.removed = self.removed
        self.keep = {u.key for n in opts.keep for u in self.named(n)}
        self.only = {u.key for n in opts.only for u in self.named(n)} if opts.only else None

    def make_context(self) -> resolver.Context:
        """Return the resolver's view of the target: its catalogue or PortIndex, its packages and the options

        @returns       the resolver context
        @throws _Stop  exit 2 when a `--map` entry names no usable target
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
        if (ctx.catalogue if brew else ctx.portindex) is None:
            self.draft.notes.append(f"the target {prefix} has no {'offline catalogue' if brew else 'PortIndex'}: "
                                    "no root can be mapped (`plan --refresh` fetches one)")
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
        """Map each root to the target after choosing the plan's Python; a `--keep` root stays unmapped"""
        roots = [r.unit.pkg for r in self.draft.roots.values() if r.key not in self.keep]
        self.ctx.python_version = resolver.plan_python(roots, self.ctx)
        for key, root in sorted(self.draft.roots.items()):
            if key in self.keep:
                root.status = KEPT
            else:
                root.mapping = resolver.resolve(root.unit.pkg, self.ctx)

    def check_drop(self) -> None:
        """Refuse a `--drop` name that is neither an unmigratable root nor a port with only inactive versions

        @throws _Stop  exit 2, a line per refused name
        """
        errors = []
        for name in self.options.drop:
            hits = []
            for unit in self.named(name):
                root = self.draft.roots.get(unit.key)
                if unit.inactive_only or (root is not None and root.mapping is not None
                                          and not resolver.accepted(root.mapping, self.ctx)):
                    hits.append(unit.key)
            if not hits:
                errors.append(f"--drop {name}: {name} is neither an unmigratable root nor a port whose every version "
                              "is inactive")
            self.dropped.update(hits)
        if errors:
            raise _Stop(EXIT_USAGE, errors)

    # Blocking findings -----------------------------------------------------------------------

    def early_blocking(self) -> None:
        """Stop on an undrivable target and on the findings that block whatever the answers

        Those are the CRITICAL ones, `ANY`, the target's `TARGET` and the named instances' `REMOVE`.

        @throws _Stop  exit 3, with the blocking findings
        """
        self.issues = list(doctor.detect_all(self.bundle, self.runner))
        context = doctor.PlanContext(target_prefix=self.target.prefix,
                                     remove_prefixes=tuple(i.prefix for i in self.removed))
        self.block(doctor.blocking(self.issues, context))

    def block(self, found: list[Issue]) -> None:
        """Stop when the target cannot be driven or a finding blocks the plan

        @param found   the findings that block the plan
        @throws _Stop  exit 3, a line per reason, with the findings
        """
        lines = []
        if not self.target.drivable:
            detail = f": {self.target.usability_detail}" if self.target.usability_detail else ""
            lines.append(f"the target {self.target.prefix} cannot be driven ({self.target.usability.value}{detail}): "
                         "`brew-ports doctor` names the repair")
        lines += doctor.blocked_by_lines(found)
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

    def questions(self) -> None:
        """Ask about the roots without an installed-on-request record, then settle each root's mapping"""
        roots = self.draft.roots
        for key, root in sorted(roots.items()):
            if root.reason == NO_RECORD and key not in self.keep and key not in self.dropped:
                answer = self.ask.choose(f"{root.unit.label()} has no installed-on-request record: migrate it as a "
                                         "root, or leave it to the target as a dependency?",
                                         ("root", "dependency"), "root")
                if answer == "dependency":
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
        if (not ok and mapping.confidence is Confidence.MEDIUM and mapping.target_name
                and not resolver.is_language(mapping) and root.key not in self.dropped):
            answer = self.ask.choose(f"Accept the MEDIUM mapping {root.unit.label()} -> {mapping.target_kind} "
                                     f"{mapping.target_name}? ({'; '.join(mapping.evidence)})", ("yes", "no"), "no")
            ok = resolver.accepted(mapping, self.ctx, answer == "yes")
        if ok:
            root.status = MIGRATED
            return
        first = mapping.evidence[0] if mapping.evidence else "no equivalent"
        if mapping.confidence is Confidence.MEDIUM and mapping.target_name and not resolver.is_language(mapping):
            first = f"the MEDIUM mapping to {mapping.target_kind} {mapping.target_name} is not accepted ({first})"
        root.note = root.note or first
        unit = root.unit
        if root.key in self.dropped:
            root.status = DROPPED
        elif resolver.keeps_data(unit.pkg):
            root.status = UNMIGRATABLE
        elif unit.kind == "cask" and self.manager is Manager.PORTS:
            root.status = DROPPED
            root.note = f"--casks map found no accepted mapping ({root.note})"
        else:
            answer = self.ask.choose(f"{unit.label()} cannot be migrated ({root.note}): keep it in {unit.prefix}, "
                                     "or drop it (removed without a replacement)?", ("keep", "drop"), "keep")
            root.status = DROPPED if answer == "drop" else UNMIGRATABLE

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
                    reason = f"language package: see {path}"
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
                self.withdraw(root, "its files outside the prefix collide with the target's port "
                              f"({', '.join(hits[:3])})")

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
                                dropped=dropped, root_owned=root_owned, ties=self.ties,
                                policy=self.options.cask_policy, only=self.only,
                                remove={i.prefix for i in self.removed}, extra_kept=dict(self.extra_kept))

    def unit(self, key: Key) -> Unit | None:
        """Return the source unit of a key

        @param key  the unit's `(prefix, kind, name key)`
        @returns    the unit, or None when no source has it
        """
        graph = self.graphs.get(key[0])
        return graph.units.get(key) if graph else None

    def compute_sets(self) -> None:
        """Compute the package sets, again after withdrawing a root that provides the login shell"""
        self.sets = plan_sets.compute(self.inputs())
        found = plan_sets.login_shell_key(self.result.environment, self.graphs, self.sets,
                                          owner_of=self.bundle.owner_of)
        if found is not None:
            key, base = found
            root = self.draft.roots.get(key)
            mapping = root.mapping if root is not None and root.status == MIGRATED else None
            executables = self.ctx.catalogue.executables if self.ctx.catalogue is not None else (lambda name: [])
            if not plan_sets.installs_basename(mapping, base, self.manager, executables):
                reason = f"provides the login shell {self.result.environment.get('login_shell')}"
                if root is not None:
                    self.withdraw(root, reason)
                else:
                    self.extra_kept[key] = reason
                self.sets = plan_sets.compute(self.inputs())
        self.draft.sets = self.sets

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
        self.draft.notes += [f"remaining cross-prefix link: {line}" for line in remaining]
        return rebuild

    def outdated(self) -> dict[str, str]:
        """Return the target's outdated formulae with the versions `brew outdated` names

        @returns  the version each formula upgrades to, by name; empty for a MacPorts target
        """
        for inst, _, inv in self.bundle.brew:
            if inst.prefix == self.target.prefix:
                return dict(inv.outdated_formulae)
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
        self.draft.upgrades = ups
        refusals = list(self.sets.refusals)
        for name, roots in sorted(ups.pinned.items()):
            refusals.append(f"the pinned {name} would be upgraded ({ups.reasons.get(name)}), which the mappings of "
                            f"{', '.join(roots) or 'the plan'} need: run `brew unpin {name}`, or plan again with those "
                            "roots in --keep")
        items, projects = plan_phases.installs(mappings)
        if self.manager is Manager.BREW:
            phase3 = plan_phases.phase3_brew(view, self.host_arch, items, projects=projects, explicit=ups.explicit,
                                             rebuilds=rebuild)
        else:
            homebrew = any(i.manager is Manager.BREW for i in self.result.instances)
            phase3 = plan_phases.phase3_ports(view, self.host_arch, items, projects=projects, homebrew_present=homebrew,
                                              rebuilds=rebuild)
        survivors = [i for i in self.result.instances if i not in self.removed]
        phase6 = plan_phases.phase6(self.removed, self.target, self.result.services, self.environ, survivors)
        phases = plan_phases.assemble(plan_phases.phase2(repairs), phase3, phase6, bool(self.removed))
        self.draft.stops = self.stops()
        self.draft.notes += self.user_jobs()
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
                program = svc.program or f"a program under {svc.instance_prefix}"
                out.append(f"will stop working: {svc.plist} runs {program}; edit or remove it by hand")
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

def _finish(draft: Draft, options: PlanOptions, run_dir: state.RunDir | None, head: Sequence[str]) -> PlanOutcome:
    """Write `plan.json`, or `plan-refused.json` with the reasons, copy it to `--out` and build the outcome

    @param draft    the pass's draft
    @param options  the plan's options
    @param run_dir  the run directory the file goes into; None writes nothing
    @param head     the report lines that come before the draft's
    @returns        the outcome
    """
    report = list(head) + plan_report.render(draft)
    ok = draft.exit_code == EXIT_OK and draft.plan is not None
    name = PLAN_FILE if ok else REFUSED_FILE
    if ok:
        text = model.to_json(draft.plan)
    else:
        text = json.dumps({"refused": {"exit": draft.exit_code, "reasons": draft.errors + draft.refusals,
                                       "blocking": model.to_plain(draft.blocking)},
                           "plan": model.to_plain(draft.plan) if draft.plan is not None else None,
                           "report": report}, indent=2, sort_keys=True)
    path = run_dir.write_json(name, text) if run_dir is not None else None
    if path is not None:
        report.append(f"{'plan written' if ok else 'refused plan written'}: {path}")
        if options.out:
            out = os.path.abspath(os.path.expanduser(options.out))
            shutil.copyfile(path, out)
            report.append(f"copied to {out}")
    return PlanOutcome(plan=draft.plan if ok else None, exit_code=draft.exit_code, report=report,
                       result_file=name if path is not None else None, path=path,
                       draft=None if ok else draft.plan)


def _refreshed(bundle: scan.ScanBundle, options: PlanOptions, runner: Any, *, ask: Any,
               state_dir: state.StateDir | None, run_dir: state.RunDir | None) -> PlanOutcome:
    """Refresh the target's catalogue, then plan over a fresh inventory

    A first pass with the default answers must find nothing blocking before anything runs.

    @param bundle     the scan
    @param options    the plan's options
    @param runner     runs the refresh and the fresh scan; it holds the host's architecture and environment
    @param ask        answers the terminal questions, the refresh's among them
    @param state_dir  the state directory, or None
    @param run_dir    the run directory, or None
    @returns          the outcome
    """
    first = _Composer(bundle, options, runner, ask=_Defaults(), state_dir=state_dir, run_dir=run_dir).run()
    if first.exit_code in (EXIT_USAGE, EXIT_PREFLIGHT) or first.target is None:
        return _finish(first, options, run_dir, ["plan --refresh: refused before the refresh; nothing was run"])
    actions = plan_phases.refresh_actions(first.target, runner.host_arch)
    commands = [doctor.describe(a) for a in actions]
    head = [f"refresh: {c}" for c in commands]
    if not ask.confirm(f"Refresh the catalogue of {first.target.prefix} now ({'; '.join(commands)})?",
                       default=False):
        draft = _Composer(bundle, options, runner, ask=ask, state_dir=state_dir, run_dir=run_dir).run()
        return _finish(draft, options, run_dir, head + ["refresh declined: planned against the catalogue as it is"])
    try:
        if any(a.sudo for a in actions):
            runner.sudo_preflight()
    except PreflightError as exc:
        return _finish(Draft(exit_code=EXIT_PREFLIGHT, target=first.target, errors=[str(exc)]), options, run_dir, head)
    if state_dir is not None and run_dir is not None:
        state_dir.touch_dirty(run_dir.run_id, "plan --refresh")
    try:
        for action in actions:
            runner.run(action)
    except (ActionFailed, EscalationFailed) as exc:
        return _finish(Draft(exit_code=EXIT_ACTION, target=first.target, errors=[f"the refresh failed: {exc}"]),
                       options, run_dir, head)
    fresh = scan.build(runner, runner.environ)
    try:
        if run_dir is not None:
            scan.write(fresh, run_dir)
        draft = _Composer(fresh, options, runner, ask=ask, state_dir=state_dir, run_dir=run_dir).run()
    finally:
        fresh.close()
    return _finish(draft, options, run_dir, head + ["refreshed: planned against a fresh inventory"])


def build(bundle: scan.ScanBundle, options: PlanOptions, runner: Any, *, ask: Any,
          state_dir: state.StateDir | None, run_dir: state.RunDir | None) -> PlanOutcome:
    """Plan `bundle` under `options`, with the report lines and the file written into `run_dir`

    `--refresh --dry-run` only lists the refresh commands.

    @param bundle     the scan
    @param options    the plan's options
    @param runner     runs the commands; it holds the host's architecture and environment
    @param ask        answers the terminal questions
    @param state_dir  the state directory, or None
    @param run_dir    the run directory, or None
    @returns          the outcome
    """
    if options.refresh and not options.dry_run:
        return _refreshed(bundle, options, runner, ask=ask, state_dir=state_dir, run_dir=run_dir)
    draft = _Composer(bundle, options, runner, ask=ask, state_dir=state_dir, run_dir=run_dir).run()
    head: list[str] = []
    if options.refresh and draft.target is not None:
        head = [f"would run: {doctor.describe(a)}"
                for a in plan_phases.refresh_actions(draft.target, runner.host_arch)]
        head.append("--dry-run: planned against the catalogue as it is")
    return _finish(draft, options, run_dir, head)


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
                ctx.console.info("plan: reusing the scan of the last ten minutes (--rescan takes a fresh one)")
            outcome = build(bundle, options, runner, ask=ctx, state_dir=ctx.state, run_dir=run_dir)
        finally:
            bundle.close()
    for line in outcome.report:
        ctx.console.out(line)
    return outcome.exit_code

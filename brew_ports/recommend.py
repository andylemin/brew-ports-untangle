"""`brew-ports recommend`: both migration directions scored on this Mac

A direction is named by its target manager, `brew` or `ports`, and scored offline from the scan and the findings.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import doctor, model, plan_sets, report, scan, state
from .context import Context
from .equiv import resolver
from .homebrew import locate as brew_locate
from .macports import bootstrap as mp_bootstrap, locate as mp_locate
from .model import Instance, Issue, Manager, Package, Severity
from .runner import BaseRunner, start_run

# The exit codes of cli.py.
EXIT_OK = 0
EXIT_FINDINGS = 1

DIRECTIONS = ("brew", "ports")
LABELS = {"brew": "Homebrew", "ports": "MacPorts"}
# The findings that make a source manager undrivable; `brew-unusable-or-dirty` also stands for a dirty repository.
UNDRIVABLE = ("ports-platform-mismatch", "ports-damaged-registry", "ports-registry-schema-update", "ports-cannot-run",
              "brew-unusable-or-dirty")
OLDEST_SUPPORTED_MACOS = 15    # HOMEBREW_MACOS_OLDEST_SUPPORTED in Homebrew 7.0.11's Library/Homebrew/brew.sh
NAMES_SHOWN = 8

# The scoring rows in table order: key, label, and the only target a row applies to (None: both).
TERMS = (
    ("coverage", "Coverage", None),
    ("unmigratable", "Unmigratable roots", None),
    ("casks", "Casks", "ports"),
    ("platform", "Platform support", "brew"),
    ("variants", "Non-default variants", "brew"),
    ("bottles", "Targets without a bottle", "brew"),
    ("services", "Services to re-create", None),
    ("undrivable", "Source manager undrivable", None),
    ("work", "Work volume", None),
)
_LABELS = {key: label for key, label, _ in TERMS}

_OLDEST_LINE = re.compile(r'^\s*HOMEBREW_MACOS_OLDEST_SUPPORTED="?(\d+)', re.M)


@dataclass
class Root:
    """A source package a plain plan migrates, and why it is a root"""

    package: Package
    why: str


@dataclass
class Term:
    """One scoring row of one direction: its points and what they count"""

    key: str
    label: str
    points: float
    detail: str


@dataclass
class RootResult:
    """A root of one direction with the mapping the offline resolver gives it"""

    instance_prefix: str
    kind: str
    name: str
    version: str
    why: str                         # requested, requested unknown, or the tie or cask rule that makes it a root
    target_kind: str
    target_name: str | None
    target_version: str | None
    confidence: str                  # the Confidence name
    accepted: bool                   # under the default plan options: mapped EXACT or HIGH, to no language package
    evidence: list[str]              # evidence[0] is an unmigratable root's reason


@dataclass
class Score:
    """One direction: its target, its sources, its roots and the scoring terms that apply to it"""

    direction: str                   # "brew" or "ports": the manager the host ends up on
    target_prefix: str | None     # the target a plain plan picks; None when the host has none
    source_prefixes: list[str]
    roots: list[RootResult]
    terms: list[Term]
    total: float
    notes: list[str] = field(default_factory=list)


@dataclass
class Recommendation:
    """Both directions scored, the table and the sentence"""

    created: str
    brew: Score
    ports: Score
    recommended: str | None       # the direction with the higher total; None when both score the same
    headline: list[str]              # the both-managers finding's counts per instance
    findings: list[str]              # the findings that make `recommend` exit 1
    table: list[str]
    sentence: str


# Roots -------------------------------------------------------------------------------

def roots(bundle: scan.ScanBundle, direction: str, target_prefix: str | None) -> list[Root]:
    """Return the roots of a plain plan with `direction` at `target_prefix`, by the planner's own rule

    So `recommend` scores exactly the packages `plan` would migrate with the default options.

    @param bundle         the scan
    @param direction      `brew` or `ports`
    @param target_prefix  the target a plain plan picks, or None when the host has none
    @returns              each root's package with its reason
    """
    target = Manager.BREW if direction == "brew" else Manager.PORTS
    return [Root(unit.pkg, why) for unit, why in plan_sets.plain_roots(bundle.result, target_prefix, target)]


# One direction --------------------------------------------------------------------------

def oldest_supported_macos(instance: Instance | None) -> int:
    """Return the oldest macOS major Homebrew supports, from the instance's `brew.sh`, else `OLDEST_SUPPORTED_MACOS`

    @param instance  the Homebrew target, or None
    @returns         the major version, such as 15
    """
    if instance is not None:
        repository = instance.repository or brew_locate.repository_of(instance.prefix)
        try:
            with open(os.path.join(repository, "Library", "Homebrew", "brew.sh"), encoding="utf-8",
                      errors="replace") as fh:
                match = _OLDEST_LINE.search(fh.read())
        except OSError:
            match = None
        if match:
            return int(match.group(1))
    return OLDEST_SUPPORTED_MACOS


def _target(instances: Sequence[Instance], direction: str, host_arch: str,
            environ: Mapping[str, str]) -> Instance | None:
    """Return the target of a plan without `--target-prefix`

    @param instances  the scan's instances
    @param direction  `brew` or `ports`
    @param host_arch  the host's architecture
    @param environ    the environment, whose `HOMEBREW_PREFIX` names a Homebrew target
    @returns          the target, or None when the host has none
    """
    if direction == "brew":
        return brew_locate.choose_target(instances, host_arch, None, environ)
    return mp_locate.choose_target(instances, host_arch, None)


def _context(bundle: scan.ScanBundle, direction: str, target: Instance | None) -> resolver.Context:
    """Return a plain plan's resolver context, offline: no runner for PyPI lookups and no Repology client

    @param bundle     the scan
    @param direction  `brew` or `ports`
    @param target     the target, or None
    @returns          the context, with the target's catalogue or PortIndex when it has one
    """
    prefix = target.prefix if target is not None else None
    installed = [p for p in bundle.result.packages if prefix is not None and p.instance_prefix == prefix]
    sources = {inst.prefix: cat for inst, cat, _ in bundle.brew if cat is not None and inst.prefix != prefix}
    if direction == "brew":
        return resolver.Context(target=Manager.BREW, catalogue=bundle.catalogue(prefix) if prefix else None,
                                installed=installed, source_catalogues=sources)
    return resolver.Context(target=Manager.PORTS, portindex=bundle.portindex(prefix) if prefix else None,
                            installed=installed, source_catalogues=sources)


def _points(value: float) -> float:
    """Round to the tenth the table shows; adding 0.0 turns -0.0 into 0.0

    @param value  a number of points
    @returns      the points to one decimal, never -0.0
    """
    return round(value, 1) + 0.0


def _term(key: str, points: float, detail: str) -> Term:
    """Build a scoring row, labelled by its key, its points rounded

    @param key     a key of `TERMS`
    @param points  the row's points
    @param detail  what the points count
    @returns       the row
    """
    return Term(key=key, label=_LABELS[key], points=_points(points), detail=detail)


def _count(n: int, noun: str) -> str:
    """Return a count with its noun, plural unless the count is one

    @param n     the count
    @param noun  the singular noun
    @returns     `1 root` or `3 roots`
    """
    return f"{n} {noun}{'' if n == 1 else 's'}"


def _listed(names: Sequence[str], noun: str) -> str:
    """Return `2 roots: a, b`, naming at most NAMES_SHOWN of them, or `none`

    @param names  the names to list
    @param noun   the singular noun that counts them
    @returns      the count and the names, or `none` without names
    """
    if not names:
        return "none"
    shown = ", ".join(names[:NAMES_SHOWN])
    if len(names) > NAMES_SHOWN:
        shown += f" and {len(names) - NAMES_SHOWN} more"
    return f"{_count(len(names), noun)}: {shown}"


class _Direction:
    """One direction's target, sources, roots and their mappings, and its scoring terms"""

    def __init__(self, bundle: scan.ScanBundle, direction: str, issues: Sequence[Issue] | None,
                 environ: Mapping[str, str]) -> None:
        """Choose the direction's target and sources, then find the roots and map each offline

        @param bundle     the scan
        @param direction  `brew` or `ports`
        @param issues     the findings, or None when none are given
        @param environ    the environment, whose `HOMEBREW_PREFIX` names a Homebrew target
        """
        result = bundle.result
        self.bundle = bundle
        self.direction = direction
        self.issues = issues
        self.facts: dict[str, Any] = result.system
        self.host_arch = self.facts.get("host_arch") or "arm64"
        self.target = _target(result.instances, direction, self.host_arch, environ)
        self.prefix = self.target.prefix if self.target is not None else None
        self.sources = [inst for inst in result.instances if inst.prefix != self.prefix]
        self.roots = roots(bundle, direction, self.prefix)
        self.ctx = _context(bundle, direction, self.target)
        self.ctx.python_version = resolver.plan_python([r.package for r in self.roots], self.ctx)
        self.mapped: list[tuple[Root, model.Mapping, bool]] = []
        for root in self.roots:
            mapping = resolver.resolve(root.package, self.ctx)
            self.mapped.append((root, mapping, resolver.accepted(mapping, self.ctx)))
        self.notes = self._notes()

    def _notes(self) -> list[str]:
        """Return the direction's notes: nothing to migrate, or why its roots cannot be mapped or counted

        @returns  the notes
        """
        notes = [] if self.roots else ["nothing to migrate in this direction"]
        unmapped = ", and every root counts as unmigratable"
        if self.target is None:
            if self.direction == "brew":
                default = brew_locate.ARM64_PREFIX if self.host_arch == "arm64" else brew_locate.USR_LOCAL
                notes.append(f"no drivable Homebrew at {default} or at HOMEBREW_PREFIX: "
                             f"`brew-ports plan --target brew` exits 3{unmapped}")
            elif any(inst.manager is Manager.PORTS for inst in self.bundle.result.instances):
                notes.append(f"several MacPorts prefixes and none at {mp_locate.DEFAULT_PREFIX}: "
                             f"`brew-ports plan --target ports` needs --target-prefix{unmapped}")
            else:
                notes.append("no MacPorts: `brew-ports bootstrap-ports` installs it" + unmapped)
        elif self.direction == "brew":
            cat = self.ctx.catalogue
            if cat is None or cat.source == "none":
                notes.append(f"{self.prefix} has no offline Homebrew catalogue{unmapped}")
            elif cat.degraded:
                notes.append(f"the Homebrew catalogue of {self.prefix} comes from {cat.source} and holds no bottle "
                             "data: targets without a bottle are not counted")
        elif self.ctx.portindex is None:
            notes.append(f"{self.prefix} has no PortIndex{unmapped}")
        notes.extend(f"the packages of {inst.prefix} are unknown (ports-damaged-registry): none of them is counted"
                     for inst in self.sources if not inst.inventory_known)
        if self.issues is None:
            notes.append("no health findings given: an undrivable source manager is not weighed")
        return notes

    def terms(self) -> list[Term]:
        """Return the scoring rows that apply to this direction, in table order

        @returns  the rows
        """
        build: dict[str, Callable[[], Term]] = {
            "coverage": self.coverage, "unmigratable": self.unmigratable, "casks": self.casks,
            "platform": self.platform, "variants": self.variants, "bottles": self.bottles,
            "services": self.services, "undrivable": self.undrivable, "work": self.work}
        return [build[key]() for key, _, only in TERMS if only in (None, self.direction)]

    def coverage(self) -> Term:
        """Score 40 times the share of roots mapped EXACT or HIGH, 40 without roots

        It counts the mappings the default options accept (no `--accept-closest`, no `--pipx`): those,
        but no language mapping.

        @returns  the row, 0 to 40 points
        """
        if not self.mapped:
            return _term("coverage", 40.0, "no roots")
        accepted = sum(1 for _, _, ok in self.mapped if ok)
        return _term("coverage", 40.0 * accepted / len(self.mapped),
                     f"{accepted} of {len(self.mapped)} roots mapped EXACT or HIGH")

    def unmigratable(self) -> Term:
        """Score -10 per root whose mapping is not accepted, floor -40

        @returns  the row, -40 to 0 points
        """
        names = [root.package.name for root, _, ok in self.mapped if not ok]
        return _term("unmigratable", max(-40.0, -10.0 * len(names)), _listed(names, "root"))

    def casks(self) -> Term:
        """Score -5 per cask of a Homebrew source, floor -25; `ports` only

        A cask that keeps data in its Caskroom is not counted here: it is an unmigratable root.

        @returns  the row, -25 to 0 points
        """
        brews = {inst.prefix for inst in self.sources if inst.manager is Manager.BREW}
        names = [p.name for p in self.bundle.result.packages
                 if p.kind == "cask" and p.instance_prefix in brews and not resolver.keeps_data(p)]
        detail = _listed(names, "cask")
        if names:
            detail += "; --casks keep (the default) leaves Homebrew installed for them"
        return _term("casks", max(-25.0, -5.0 * len(names)), detail)

    def platform(self) -> Term:
        """Score -30 on x86_64, else -20 on a macOS older than Homebrew's three supported releases; `brew` only

        @returns  the row: -30, -20 or 0 points
        """
        arch = (self.target.arch if self.target is not None else None) or self.facts.get("host_arch")
        if arch == "x86_64":
            return _term("platform", -30.0, "x86_64: Homebrew supports Intel Macs at Tier 3 only")
        version = self.facts.get("macos")
        try:
            major = mp_bootstrap.macos_major(version)
        except mp_bootstrap.BootstrapError:
            return _term("platform", 0.0, "the macOS version is unknown")
        oldest = oldest_supported_macos(self.target)
        if major < oldest:
            return _term("platform", -20.0, f"macOS {version} is older than Homebrew's three supported releases "
                                            f"({oldest} and newer)")
        return _term("platform", 0.0, f"macOS {version} on {arch or 'arm64'} is supported")

    def variants(self) -> Term:
        """Score -3 per root with non-default variants, which Homebrew lacks, floor -20; `brew` only

        @returns  the row, -20 to 0 points
        """
        names = [f"{root.package.name} ({' '.join(root.package.requested_variants)})"
                 for root, _, _ in self.mapped if root.package.kind == "port" and root.package.requested_variants]
        return _term("variants", max(-20.0, -3.0 * len(names)), _listed(names, "root"))

    def bottles(self) -> Term:
        """Score -2 per accepted formula target without a bottle in the catalogue, floor -20; `brew` only

        A degraded catalogue has no bottle data, so it counts none.

        @returns  the row, -20 to 0 points
        """
        cat = self.ctx.catalogue
        if cat is None or cat.degraded:
            return _term("bottles", 0.0, "no bottle data")
        names = [f"{mapping.target_name} (for {root.package.name})" for root, mapping, ok in self.mapped
                 if ok and mapping.target_kind == "formula" and not cat.has_bottle(mapping.target_name or "")]
        return _term("bottles", max(-20.0, -2.0 * len(names)), _listed(names, "target"))

    def services(self) -> Term:
        """Score -2 per owned service of an accepted root that is not an adoption

        The services of a root that is not accepted stay where they are; an adopted cask's belong to the target.

        @returns  the row, 0 points or fewer, without a floor
        """
        names = [f"{svc.label} ({root.package.name})" for root, mapping, ok in self.mapped
                 if ok and not mapping.adopt for svc in root.package.services if svc.owned]
        return _term("services", -2.0 * len(names), _listed(names, "service"))

    def undrivable(self) -> Term:
        """Score +10 for leaving a source manager that an `UNDRIVABLE` finding above INFO marks undrivable

        A `brew-unusable-or-dirty` at INFO is a check that did not run; at HIGH, a dirty repository counts as well.

        @returns  the row: 10 or 0 points
        """
        if self.issues is None:
            return _term("undrivable", 0.0, "not weighed")
        prefixes = {inst.prefix for inst in self.sources}
        found: list[str] = []
        for issue in self.issues:
            text = f"{issue.code} at {issue.instance_prefix}"
            if issue.code in UNDRIVABLE and issue.severity > Severity.INFO and issue.instance_prefix in prefixes \
                    and text not in found:
                found.append(text)
        return _term("undrivable", 10.0 if found else 0.0, ", ".join(found) or "none")

    def work(self) -> Term:
        """Score -0.1 per root to migrate, floor -20

        @returns  the row, -20 to 0 points
        """
        return _term("work", max(-20.0, -0.1 * len(self.mapped)), _count(len(self.mapped), "root"))


def _root_result(root: Root, mapping: model.Mapping, ok: bool) -> RootResult:
    """Return a root with its mapping, as `recommend` reports it

    @param root     a root of the direction
    @param mapping  the offline resolver's mapping of it
    @param ok       whether the default options accept the mapping
    @returns        the root's result
    """
    pkg = root.package
    return RootResult(instance_prefix=pkg.instance_prefix, kind=pkg.kind, name=pkg.name, version=pkg.version,
                      why=root.why, target_kind=mapping.target_kind, target_name=mapping.target_name,
                      target_version=mapping.target_version, confidence=mapping.confidence.name, accepted=ok,
                      evidence=list(mapping.evidence))


def score(bundle: scan.ScanBundle, direction: str, *, issues: Sequence[Issue] | None = None,
          environ: Mapping[str, str] | None = None) -> Score:
    """Score one direction, its total the sum of its terms

    @param bundle       the scan
    @param direction    `brew` or `ports`
    @param issues       the findings; without them the undrivable term is 0
    @param environ      the environment, whose `HOMEBREW_PREFIX` names a Homebrew target
    @returns            the direction's score
    @throws ValueError  for a direction other than `brew` or `ports`
    """
    if direction not in DIRECTIONS:
        raise ValueError(f"a direction is brew or ports, not {direction!r}")
    weighed = _Direction(bundle, direction, issues, environ or {})
    terms = weighed.terms()
    return Score(direction=direction, target_prefix=weighed.prefix,
                 source_prefixes=[inst.prefix for inst in weighed.sources],
                 roots=[_root_result(root, mapping, ok) for root, mapping, ok in weighed.mapped], terms=terms,
                 total=_points(sum(t.points for t in terms)), notes=weighed.notes)


# Both directions -------------------------------------------------------------------------

def _winner(brew: Score, ports: Score) -> Score | None:
    """Return the direction with the higher total

    @param brew   the score of the `brew` direction
    @param ports  the score of the `ports` direction
    @returns      that score, or None on a tie
    """
    if brew.total == ports.total:
        return None
    return brew if brew.total > ports.total else ports


def findings(issues: Iterable[Issue]) -> list[str]:
    """Return the findings that make `recommend` exit 1: both managers present, or an `UNDRIVABLE` one above INFO

    Every other finding is `doctor`'s to report.

    @param issues  the findings of the scan
    @returns       their codes, each once, in the order found
    """
    out: list[str] = []
    for issue in issues:
        counts = issue.code == "env-both-managers" or (issue.code in UNDRIVABLE and issue.severity > Severity.INFO)
        if counts and issue.code not in out:
            out.append(issue.code)
    return out


def table(brew: Score, ports: Score) -> list[str]:
    """Return the scoring table: a row per term with each direction's points, or `n/a`, then the totals

    @param brew   the score of the `brew` direction
    @param ports  the score of the `ports` direction
    @returns      the table's lines, headers first
    """
    headers = ["Term", "target brew", "target ports"]
    columns = ((brew, len(headers[1])), (ports, len(headers[2])))

    def cell(s: Score, key: str, width: int) -> str:
        found = next((t for t in s.terms if t.key == key), None)
        return (f"{found.points:.1f}" if found is not None else "n/a").rjust(width)

    rows = [[label] + [cell(s, key, width) for s, width in columns] for key, label, _ in TERMS]
    rows.append(["Total"] + [f"{s.total:.1f}".rjust(width) for s, width in columns])
    return report.table(rows, headers)


def sentence(brew: Score, ports: Score) -> str:
    """Return the closing sentence: the direction with the higher score, or no recommendation on a tie

    @param brew   the score of the `brew` direction
    @param ports  the score of the `ports` direction
    @returns      the sentence
    """
    won = _winner(brew, ports)
    if won is None:
        return (f"No recommendation: both targets score {brew.total:.1f}; `brew-ports plan` needs --target brew or "
                "--target ports.")
    lost = ports if won is brew else brew
    then = (f"`brew-ports plan --target {won.direction}` plans the migration" if won.roots
            else "nothing to migrate in that direction")
    return (f"Recommendation: target {won.direction} ({LABELS[won.direction]}), {won.total:.1f} points against "
            f"{lost.total:.1f} for target {lost.direction}; {then}.")


def recommend(bundle: scan.ScanBundle, issues: Sequence[Issue], *,
              environ: Mapping[str, str] | None = None) -> Recommendation:
    """Score both directions, with the both-managers counts as the headline, then the table and the sentence

    @param bundle   the scan
    @param issues   the findings of the scan
    @param environ  the environment, whose `HOMEBREW_PREFIX` names a Homebrew target
    @returns        the recommendation
    """
    brew = score(bundle, "brew", issues=issues, environ=environ)
    ports = score(bundle, "ports", issues=issues, environ=environ)
    won = _winner(brew, ports)
    both = next((issue for issue in issues if issue.code == "env-both-managers"), None)
    return Recommendation(created=state.now_iso(), brew=brew, ports=ports,
                          recommended=won.direction if won is not None else None,
                          headline=list(both.evidence) if both is not None else [], findings=findings(issues),
                          table=table(brew, ports), sentence=sentence(brew, ports))


# The command ------------------------------------------------------------------------------

def _heading(s: Score) -> str:
    """Return the heading of a direction's section: its target and its sources

    @param s  a direction's score
    @returns  the heading line
    """
    where = (f"{LABELS[s.direction]} at {s.target_prefix}" if s.target_prefix
             else f"no {LABELS[s.direction]} instance")
    return f"target {s.direction}: {where}; sources {', '.join(s.source_prefixes) or 'none'}"


def _root_line(r: RootResult) -> str:
    """Return the verbose line of a root: its mapping and confidence, and the reason when it is not accepted

    @param r  a root's result
    @returns  the line
    """
    head = f"root {r.name} ({r.instance_prefix}, {r.why})"
    target = " ".join(part for part in (r.target_kind, r.target_name, r.target_version) if part)
    if r.accepted:
        return f"{head}: {target} ({r.confidence})"
    reason = r.evidence[0] if r.evidence else "no evidence"
    if r.target_name:
        return f"{head}: {target} ({r.confidence}), not accepted: {reason}"
    return f"{head}: unmigratable ({r.confidence}): {reason}"


def render(rec: Recommendation, verbose: bool = False) -> list[str]:
    """Return the text of `recommend`: the headline, the table, each direction's terms and notes, the sentence

    @param rec      the recommendation
    @param verbose  whether each root's line follows its direction's notes
    @returns        the lines
    """
    lines: list[str] = []
    if rec.headline:
        lines += ["Both managers present"] + ["  " + line for line in rec.headline] + [""]
    lines += rec.table
    for s in (rec.brew, rec.ports):
        lines += ["", _heading(s)]
        lines += [f"  {t.label}: {t.detail}" for t in s.terms if t.key == "coverage" or t.points]
        lines += [f"  note: {note}" for note in s.notes]
        if verbose:
            lines += ["  " + _root_line(r) for r in s.roots]
    return lines + ["", rec.sentence]


def cmd_recommend(ctx: Context, make_runner: Callable[[Context, state.RunDir], BaseRunner] | None = None) -> int:
    """Run `brew-ports recommend`: the scan, the findings, both scores, the text or `--json`; exit 1 on findings

    A scan younger than ten minutes is reused unless a mutating command ran since or `--rescan` is given.

    @param ctx          the command's context
    @param make_runner  builds the runner from the context and the run directory; None for `command_runner`
    @returns            `EXIT_FINDINGS` when a finding counts, else `EXIT_OK`
    """
    run_dir, runner = start_run(ctx, 0, make_runner)
    with runner.signals():
        bundle, reused = scan.obtain(ctx.state, run_dir, runner, ctx.environ, rescan=ctx.args.rescan)
        try:
            rec = recommend(bundle, doctor.detect_all(bundle, runner), environ=ctx.environ)
        finally:
            bundle.close()
    if ctx.args.json:
        ctx.console.json(rec)
    else:
        if reused:
            ctx.console.info("recommend: reusing the scan of the last ten minutes (--rescan takes a fresh one)")
        for line in render(rec, verbose=ctx.console.verbose):
            ctx.console.out(line)
    return EXIT_FINDINGS if rec.findings else EXIT_OK

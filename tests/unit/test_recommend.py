"""`recommend`: each row of the scoring table, the roots, the offline resolver, the text and the exit codes"""

import contextlib
import io
import json
import os
import sys
import unittest
from typing import Any
from unittest import mock

from brew_ports import cli, recommend, runner as runner_mod
from brew_ports.context import Context
from brew_ports.equiv import resolver
from brew_ports.homebrew.catalogue import Catalogue
from brew_ports.model import Severity, Usability
from tests.unit.fixtures.doctor.builders import health_modules, service
from tests.unit.fixtures.recommend.builders import Host, brew_sh, context, issue, runner_factory
from tests.unit.helpers import TempDirTest


def term(score, key):
    """Return one scoring row of a direction

    @param score  the direction's score
    @param key    the row's key, such as `coverage`
    @returns      the row
    """
    return next(t for t in score.terms if t.key == key)


def keys(score):
    """Return the keys of a direction's scoring rows

    @param score  the direction's score
    @returns      the keys, in table order
    """
    return [t.key for t in score.terms]


class RecommendCase(TempDirTest):
    """A synthetic host below the test's directory, scored one direction at a time"""

    def setUp(self):
        super().setUp()
        self.host = Host(self.tmp)

    def both(self):
        """Add Homebrew and MacPorts at their default prefixes"""
        self.host.add_brew()
        self.host.add_ports()

    def score(self, direction, issues=()):
        """Score one direction of the host

        @param direction  `brew` or `ports`
        @param issues     the findings
        @returns          the direction's score
        """
        return recommend.score(self.host.bundle(), direction, issues=list(issues), environ=self.host.environ)


class CoverageTest(RecommendCase):
    """The coverage row: the share of roots mapped EXACT or HIGH"""

    def test_coverage_is_the_share_mapped_exact_or_high(self):
        self.both()
        self.host.port("wget", "1.25.0", revision=1)
        self.host.port("gsed", "4.9")
        self.host.port("dd_rescue", "1.99.21", homepage="https://www.garloff.de/kurt/linux/ddrescue/",
                       executables=["dd_rescue"])
        self.host.port("nosuchport")
        s = self.score("brew")
        self.assertEqual((term(s, "coverage").points, term(s, "coverage").detail),
                         (20.0, "2 of 4 roots mapped EXACT or HIGH"))
        self.assertEqual(sorted((r.name, r.target_name or "", r.confidence, r.accepted) for r in s.roots),
                         sorted([("wget", "wget", "EXACT", True), ("gsed", "gnu-sed", "EXACT", True),
                                 ("dd_rescue", "ddrescue", "MEDIUM", False), ("nosuchport", "", "NONE", False)]))

    def test_coverage_is_40_without_roots_with_the_note(self):
        self.both()
        self.host.formula("wget")
        s = self.score("brew")
        self.assertEqual((s.roots, term(s, "coverage").points, term(s, "coverage").detail), ([], 40.0, "no roots"))
        self.assertIn("nothing to migrate in this direction", s.notes)


class UnmigratableTest(RecommendCase):
    """The unmigratable row: the roots whose mapping the default options refuse"""

    def test_unmigratable_roots_cost_10_each_down_to_40(self):
        self.both()
        self.host.port("nosuch1")
        self.host.port("nosuch2")
        self.assertEqual(term(self.score("brew"), "unmigratable").points, -20.0)
        for name in ("nosuch3", "nosuch4", "nosuch5"):
            self.host.port(name)
        t = term(self.score("brew"), "unmigratable")
        self.assertEqual((t.points, t.detail), (-40.0, "5 roots: nosuch1, nosuch2, nosuch3, nosuch4, nosuch5"))

    def test_a_language_package_is_unmigratable_offline(self):
        self.both()
        self.host.formula("black")
        root = self.score("ports").roots[0]
        self.assertEqual((root.target_kind, root.confidence, root.accepted), ("pip", "LOW", False))


class CasksTest(RecommendCase):
    """The casks row of a MacPorts target, and the casks a Homebrew target adopts"""

    def test_casks_cost_5_each_under_a_ports_target(self):
        self.both()
        self.host.cask("firefox")
        self.host.cask("vlc")
        self.host.cask("miniconda", caskroom_data=["base"])
        s = self.score("ports")
        t = term(s, "casks")
        self.assertEqual((t.points, t.detail), (-10.0, "2 casks: firefox, vlc; --casks keep (the default) leaves "
                                                       "Homebrew installed for them"))
        self.assertEqual([(r.name, r.why, r.accepted, r.evidence[0]) for r in s.roots],
                         [("miniconda", "keeps data in its Caskroom", False, "keeps data in base")])
        for token in ("zoom", "virtualbox", "docker-desktop", "font-fira-code"):
            self.host.cask(token)
        self.assertEqual(term(self.score("ports"), "casks").points, -25.0)
        self.assertNotIn("casks", keys(self.score("brew")))

    def test_a_brew_target_adopts_every_source_cask(self):
        # The planner's rule: a Homebrew target adopts each source cask, requested or not.
        self.host.add_brew()
        self.host.add_brew(self.host.usr_local)
        self.host.cask("firefox", prefix=self.host.usr_local)
        self.host.cask("vlc", prefix=self.host.usr_local, requested=False)
        roots = self.score("brew").roots
        self.assertEqual(sorted((r.name, r.target_kind, r.confidence, r.accepted) for r in roots),
                         [("firefox", "cask", "EXACT", True), ("vlc", "cask", "EXACT", True)])


class PlatformTest(RecommendCase):
    """The platform row of a Homebrew target: the architecture and the macOS release"""

    def test_a_supported_macos_on_arm64_costs_nothing(self):
        self.both()
        t = term(self.score("brew"), "platform")
        self.assertEqual((t.points, t.detail), (0.0, "macOS 26.1 on arm64 is supported"))
        self.assertNotIn("platform", keys(self.score("ports")))

    def test_an_unsupported_macos_costs_20(self):
        self.both()
        self.host.system["macos"] = "14.7.1"
        t = term(self.score("brew"), "platform")
        self.assertEqual((t.points, t.detail),
                         (-20.0, "macOS 14.7.1 is older than Homebrew's three supported releases (15 and newer)"))

    def test_intel_costs_30(self):
        self.host.add_brew(arch="x86_64")
        self.host.add_ports()
        self.host.system.update(host_arch="x86_64", macos="14.7.1")
        t = term(self.score("brew"), "platform")
        self.assertEqual((t.points, t.detail), (-30.0, "x86_64: Homebrew supports Intel Macs at Tier 3 only"))

    def test_oldest_supported_release_from_brew_sh(self):
        self.both()
        brew_sh(self.host.brew_prefix, "27")
        self.assertEqual(term(self.score("brew"), "platform").points, -20.0)
        target = self.host.brew[0][0]
        self.assertEqual(recommend.oldest_supported_macos(target), 27)
        self.assertEqual(recommend.oldest_supported_macos(None), recommend.OLDEST_SUPPORTED_MACOS)


class VariantsTest(RecommendCase):
    """The variants row of a Homebrew target"""

    def test_non_default_variants_cost_3_per_root(self):
        self.both()
        self.host.port("wget", "1.25.0", revision=1, requested_variants=["+gnutls"])
        self.host.port("gsed", "4.9")
        t = term(self.score("brew"), "variants")
        self.assertEqual((t.points, t.detail), (-3.0, "1 root: wget (+gnutls)"))
        for i in range(7):
            self.host.port(f"nosuch{i}", requested_variants=["+x11", "-quartz"])
        self.assertEqual(term(self.score("brew"), "variants").points, -20.0)
        self.assertNotIn("variants", keys(self.score("ports")))


class BottlesTest(RecommendCase):
    """The bottles row of a Homebrew target, and a catalogue without bottle data"""

    def test_targets_without_a_bottle_cost_2_per_root(self):
        self.both()
        self.host.port("wget", "1.25.0", revision=1)
        self.host.port("gsed", "4.9")
        self.host.port("nosuch")
        t = term(self.score("brew"), "bottles")
        self.assertEqual((t.points, t.detail), (-2.0, "1 target: gnu-sed (for gsed)"))
        self.assertNotIn("bottles", keys(self.score("ports")))

    def test_the_bottle_term_stops_at_20(self):
        payload = {"formulae": {f"tool{i}": {"stable_version": "1.0"} for i in range(11)}}
        self.host.add_brew(catalogue=Catalogue.from_payload(payload, home=self.host.home))
        self.host.add_ports()
        for i in range(11):
            self.host.port(f"tool{i}")
        self.assertEqual(term(self.score("brew"), "bottles").points, -20.0)

    def test_a_catalogue_without_bottle_data_counts_none(self):
        self.host.add_brew(catalogue=Catalogue(formula_names=["tool0"], source="taps", home=self.host.home))
        self.host.add_ports()
        self.host.port("tool0")
        s = self.score("brew")
        self.assertEqual((s.roots[0].accepted, term(s, "bottles").points), (True, 0.0))
        self.assertIn(f"the Homebrew catalogue of {self.host.brew_prefix} comes from taps and holds no bottle data: "
                      "targets without a bottle are not counted", s.notes)


class ServicesTest(RecommendCase):
    """The services row: the owned services the target re-creates"""

    def test_services_to_recreate_cost_2_each(self):
        self.both()
        plist = "/Library/LaunchDaemons/org.macports.%s.plist"
        self.host.port("wget", "1.25.0", revision=1,
                       services=[service("org.macports.wget", plist % "wget", self.host.ports_prefix, "wget",
                                         kind="port")])
        self.host.port("nosuch", services=[service("org.macports.nosuch", plist % "nosuch", self.host.ports_prefix,
                                                   "nosuch", kind="port")])
        self.host.port("gsed", "4.9", services=[service("org.example.gsed", "/Users/alice/Library/LaunchAgents/x.plist",
                                                         self.host.ports_prefix, "gsed", kind="port", owned=False)])
        t = term(self.score("brew"), "services")
        self.assertEqual((t.points, t.detail), (-2.0, "1 service: org.macports.wget (wget)"))

    def test_an_adopted_casks_services_are_not_recreated(self):
        self.host.add_brew()
        self.host.add_brew(self.host.usr_local)
        agent = service("org.mozilla.updater", "/Users/alice/Library/LaunchAgents/org.mozilla.updater.plist",
                        self.host.usr_local, "firefox", kind="cask")
        self.host.cask("firefox", prefix=self.host.usr_local, services=[agent])
        s = self.score("brew")
        self.assertEqual((s.roots[0].accepted, term(s, "services").points), (True, 0.0))


class UndrivableTest(RecommendCase):
    """The undrivable row: the findings that mark a source manager undrivable"""

    def test_leaving_an_undrivable_source_manager_adds_10(self):
        self.both()
        for code in ("ports-platform-mismatch", "ports-damaged-registry", "ports-registry-schema-update",
                     "ports-cannot-run"):
            t = term(self.score("brew", [issue(code, self.host.ports_prefix)]), "undrivable")
            self.assertEqual((t.points, t.detail), (10.0, f"{code} at {self.host.ports_prefix}"))
        dirty = issue("brew-unusable-or-dirty", self.host.brew_prefix)
        self.assertEqual(term(self.score("ports", [dirty, dirty]), "undrivable").points, 10.0)
        self.assertEqual(term(self.score("ports", [dirty]), "undrivable").detail,
                         f"brew-unusable-or-dirty at {self.host.brew_prefix}")

    def test_target_info_and_other_findings_add_nothing(self):
        self.both()
        mismatch = issue("ports-platform-mismatch", self.host.ports_prefix)
        self.assertEqual(term(self.score("ports", [mismatch]), "undrivable").points, 0.0)
        skipped = issue("brew-unusable-or-dirty", self.host.brew_prefix, severity=Severity.INFO)
        self.assertEqual(term(self.score("ports", [skipped]), "undrivable").points, 0.0)
        missing = issue("ports-missing-file", self.host.ports_prefix)
        self.assertEqual(term(self.score("brew", [missing]), "undrivable").points, 0.0)

    def test_without_findings_the_term_is_not_weighed(self):
        self.both()
        s = recommend.score(self.host.bundle(), "brew", environ=self.host.environ)
        self.assertEqual((term(s, "undrivable").points, term(s, "undrivable").detail), (0.0, "not weighed"))
        self.assertIn("no health findings given: an undrivable source manager is not weighed", s.notes)


class WorkVolumeTest(RecommendCase):
    """The work volume row: the number of roots"""

    def test_work_volume_costs_a_tenth_per_root(self):
        self.both()
        for i in range(3):
            self.host.port(f"nosuch{i}")
        t = term(self.score("brew"), "work")
        self.assertEqual((t.points, t.detail), (-0.3, "3 roots"))
        for i in range(3, 201):
            self.host.port(f"nosuch{i}")
        self.assertEqual(term(self.score("brew"), "work").points, -20.0)


class RootsTest(RecommendCase):
    """The roots of a plain plan, by the planner's own rule"""

    def roots(self, direction="brew", target=None):
        """Return the roots of a plain plan of the host

        @param direction  `brew` or `ports`
        @param target     the target's prefix; None for the Homebrew target's
        @returns          each root's name, version and reason
        """
        return [(r.package.name, r.package.version, r.why) for r in
                recommend.roots(self.host.bundle(), direction, target or self.host.brew_prefix)]

    def test_a_ports_root_is_its_active_row(self):
        self.both()
        self.host.port("wget", "1.24.5", active=False)
        self.host.port("wget", "1.25.0", revision=1)
        self.host.port("gsed", "4.8", active=False)
        self.assertEqual(self.roots(), [("wget", "1.25.0_1", "installed on request")])

    def test_requested_none_is_a_root_by_default(self):
        self.both()
        self.host.port("wget", "1.25.0", requested=None)
        self.host.port("libidn2", requested=False)
        self.assertEqual(self.roots(), [("wget", "1.25.0_0", "no installed-on-request record")])

    def test_dependencies_with_state_are_roots(self):
        self.both()
        prefix = self.host.ports_prefix
        dbus = service("org.freedesktop.dbus-system", "/Library/LaunchDaemons/org.freedesktop.dbus-system.plist",
                       prefix, "dbus", kind="port")
        self.host.port("dbus", "1.16.2", requested=False, services=[dbus])
        self.host.port("python313", "3.13.18", requested=False)
        self.host.port("nodejs22", "22.23.4", requested=False)
        self.host.port("mariadb", "11.4.9", requested=False)
        self.host.port("zlib", "1.3.1", requested=False)
        os.makedirs(os.path.join(prefix, "var", "db", "mariadb"))
        self.host.extras = {
            "python": [{"version": "3.13", "instance_prefix": prefix, "location": "prefix",
                        "site_packages": prefix + "/Library/Frameworks/Python.framework/Versions/3.13/lib/python3.13/"
                                                  "site-packages", "dists": [{"name": "requests", "version": "2.32.5"}],
                        "scripts": []}],
            "npm": [{"instance_prefix": prefix, "name": "typescript", "version": "5.9.3",
                     "path": prefix + "/lib/node_modules/typescript"}]}
        site = prefix + "/Library/Frameworks/Python.framework/Versions/3.13/lib/python3.13/site-packages"
        self.assertEqual(sorted(self.roots()), sorted([
            ("dbus", "1.16.2_0", "owns the service org.freedesktop.dbus-system"),
            ("python313", "3.13.18_0", f"owns interpreter extras (python 3.13 packages in {site})"),
            ("nodejs22", "22.23.4_0", "owns interpreter extras (1 npm entry)"),
            ("mariadb", "11.4.9_0", f"owns the data directory {prefix}/var/db/mariadb")]))

    def test_the_python_of_pipx_venvs_is_a_root(self):
        self.both()
        self.host.formula("python@3.13", requested=False)
        self.host.formula("pcre2", requested=False)
        self.host.extras = {"pipx": [{"venv": "/Users/alice/.local/pipx/venvs/black", "name": "black",
                                      "version": "25.9.0", "home": self.host.brew_prefix + "/opt/python@3.13/bin",
                                      "instance_prefix": self.host.brew_prefix}]}
        self.assertEqual(self.roots("ports", self.host.ports_prefix),
                         [("python@3.13", "3.13.18", "owns interpreter extras (the pipx venv black)")])

    def test_every_other_instance_is_a_source(self):
        self.host.add_brew()
        self.host.add_brew(self.host.usr_local)
        self.host.add_ports()
        self.host.formula("wget")
        self.host.formula("gnu-sed", prefix=self.host.usr_local)
        self.host.port("gsed", "4.9")
        s = self.score("brew")
        self.assertEqual((s.target_prefix, s.source_prefixes),
                         (self.host.brew_prefix, [self.host.usr_local, self.host.ports_prefix]))
        self.assertEqual([(r.instance_prefix, r.name, r.target_name) for r in s.roots],
                         [(self.host.usr_local, "gnu-sed", "gnu-sed"), (self.host.ports_prefix, "gsed", "gnu-sed")])


class TargetTest(RecommendCase):
    """Each direction's target, its offline resolver, and a target that is missing or lacks a catalogue"""

    def test_the_resolver_runs_offline(self):
        self.both()
        self.host.formula("wget")
        self.host.formula("black")
        self.host.port("gsed", "4.9")
        seen = []
        real = resolver.resolve

        def spy(pkg, ctx):
            seen.append(ctx)
            return real(pkg, ctx)
        with mock.patch("brew_ports.equiv.resolver.resolve", spy):
            self.score("brew")
            self.score("ports")
        self.assertEqual(len(seen), 3)
        for ctx in seen:
            self.assertEqual((ctx.runner, ctx.repology, ctx.lang_packages, ctx.accept_medium, ctx.maps),
                             (None, None, "report", False, {}))

    def test_without_macports_every_root_is_unmigratable(self):
        self.host.add_brew()
        self.host.formula("wget")
        s = self.score("ports")
        self.assertIsNone(s.target_prefix)
        self.assertEqual((term(s, "coverage").points, term(s, "unmigratable").points), (0.0, -10.0))
        self.assertEqual(s.roots[0].evidence, ["no MacPorts catalogue to map against"])
        self.assertIn("no MacPorts: `brew-ports bootstrap-ports` installs it, and every root counts as unmigratable",
                      s.notes)

    def test_undrivable_homebrew_makes_all_sources(self):
        self.host.add_brew(usability=Usability.CANNOT_RUN, drivable=False)
        self.host.add_ports()
        self.host.formula("wget")
        self.host.port("gsed", "4.9")
        s = self.score("brew")
        self.assertEqual((s.target_prefix, s.source_prefixes), (None, [self.host.brew_prefix, self.host.ports_prefix]))
        self.assertEqual([r.accepted for r in s.roots], [False, False])
        self.assertIn("no drivable Homebrew at /opt/homebrew or at HOMEBREW_PREFIX: `brew-ports plan --target brew` "
                      "exits 3, and every root counts as unmigratable", s.notes)

    def test_a_target_without_its_catalogue(self):
        self.host.add_brew()
        self.host.add_ports(index=False)
        self.host.formula("wget")
        s = self.score("ports")
        self.assertEqual((s.target_prefix, s.roots[0].accepted), (self.host.ports_prefix, False))
        self.assertIn(f"{self.host.ports_prefix} has no PortIndex, and every root counts as unmigratable", s.notes)


class RecommendationTest(RecommendCase):
    """Both directions scored: the totals, the table, the sentence and the findings"""

    def host_with_both(self):
        """Add both managers, Homebrew with wget and foo-bar, MacPorts with wget"""
        self.both()
        self.host.formula("wget")
        self.host.formula("foo-bar")
        self.host.port("wget", "1.25.0", revision=1)

    def test_the_higher_total_is_the_recommendation(self):
        self.host_with_both()
        both = issue("env-both-managers", None, Severity.INFO, [f"{self.host.brew_prefix}: 2 formulae, 0 casks",
                                                               f"{self.host.ports_prefix}: 1 ports (1 active)"])
        rec = recommend.recommend(self.host.bundle(), [both], environ=self.host.environ)
        self.assertEqual((rec.brew.total, rec.ports.total, rec.recommended), (39.9, 9.8, "brew"))
        self.assertEqual(rec.sentence, "Recommendation: target brew (Homebrew), 39.9 points against 9.8 for target "
                                       "ports; `brew-ports plan --target brew` plans the migration.")
        self.assertEqual((rec.headline, rec.findings), (both.evidence, ["env-both-managers"]))

    def test_the_table_has_a_row_per_term(self):
        self.host_with_both()
        rec = recommend.recommend(self.host.bundle(), [], environ=self.host.environ)
        rows = {line.split("  ")[0]: line.split() for line in rec.table[2:]}
        self.assertEqual(rec.table[0].split(), ["Term", "target", "brew", "target", "ports"])
        self.assertEqual(list(rows), [label for _, label, _ in recommend.TERMS] + ["Total"])
        self.assertEqual(rows["Coverage"][-2:], ["40.0", "20.0"])
        self.assertEqual(rows["Casks"][-2:], ["n/a", "0.0"])
        self.assertEqual(rows["Platform support"][-2:], ["0.0", "n/a"])
        self.assertEqual(rows["Total"], ["Total", "39.9", "9.8"])
        self.assertEqual(len({len(line) for line in rec.table[1:]}), 1)

    def test_a_tie_recommends_nothing(self):
        rec = recommend.recommend(self.host.bundle(), [], environ=self.host.environ)
        self.assertEqual((rec.brew.total, rec.ports.total, rec.recommended), (40.0, 40.0, None))
        self.assertEqual(rec.sentence, "No recommendation: both targets score 40.0; `brew-ports plan` needs "
                                       "--target brew or --target ports.")

    def test_a_winner_without_roots_has_nothing_to_migrate(self):
        self.host.add_brew()
        self.host.formula("wget")
        rec = recommend.recommend(self.host.bundle(), [], environ=self.host.environ)
        self.assertEqual(rec.recommended, "brew")
        self.assertTrue(rec.sentence.endswith("; nothing to migrate in that direction."), rec.sentence)

    def test_findings_are_both_managers_and_undrivable(self):
        found = [issue("system-low-disk-space", self.host.brew_prefix),
                 issue("brew-unusable-or-dirty", self.host.brew_prefix, Severity.INFO),
                 issue("ports-cannot-run", self.host.ports_prefix), issue("env-both-managers", None, Severity.INFO),
                 issue("ports-cannot-run", self.host.ports_prefix + "2"),
                 issue("brew-broken-linkage", self.host.brew_prefix)]
        self.assertEqual(recommend.findings(found), ["ports-cannot-run", "env-both-managers"])
        self.assertEqual(recommend.findings([]), [])

    def test_an_unknown_direction_is_refused(self):
        with self.assertRaises(ValueError):
            recommend.score(self.host.bundle(), "nix")


class CommandTest(RecommendCase):
    """`brew-ports recommend`: the scan, the findings, the text or JSON, and the exit code"""

    def setUp(self):
        super().setUp()
        self.ctx: Context | None = None
        self.made: list[runner_mod.FakeRunner] = []
        self.calls: list[dict[str, Any]] = []

    def run_command(self, bundle, mods=None, reused=False, verbose=False, **args):
        """Run `brew-ports recommend` over a bundle, recording the runners made and the scans asked for

        @param bundle   the scan `scan.obtain` hands back
        @param mods     the `sys.modules` entries of the health modules; None for `health_modules()`
        @param reused   whether the scan counts as reused
        @param verbose  whether the console is verbose
        @param args     the command's argument values, such as `json=True`
        @returns        the exit code
        """
        self.ctx = context(self.state_dir(), self.host, verbose=verbose, **args)
        self.made = []
        self.calls = []

        def obtain(_state_dir, run_dir, _runner, _environ, *, rescan=False, _deep=False):
            """Record the call in `calls` and return the test's bundle

            @param _state_dir  the state directory
            @param run_dir     the run directory, which is recorded
            @param _runner     the runner
            @param _environ    the environment
            @param rescan      the option to take a fresh scan, which is recorded
            @param _deep       the option to read every formula's linkage
            @returns           `(bundle, reused)`
            """
            self.calls.append({"rescan": rescan, "run_dir": run_dir})
            return bundle, reused
        with mock.patch("brew_ports.scan.obtain", side_effect=obtain), \
                mock.patch.dict(sys.modules, mods or health_modules()):
            return recommend.cmd_recommend(self.ctx, make_runner=runner_factory(self.made))

    def stdout(self):
        """Return what the last command printed

        @returns  the console's output
        """
        return self.ctx.console.stream.getvalue()

    def test_both_managers_exit_1_with_json(self):
        self.both()
        self.host.formula("wget")
        self.host.port("wget", "1.25.0", revision=1)
        bundle = self.host.bundle()
        code = self.run_command(bundle, json=True)
        self.assertEqual(code, recommend.EXIT_FINDINGS)
        data = json.loads(self.stdout())
        self.assertEqual(set(data), {"created", "brew", "ports", "recommended", "headline", "findings", "table",
                                     "sentence"})
        self.assertEqual((data["findings"], data["headline"]),
                         (["env-both-managers"], [f"{self.host.brew_prefix}: 1 formulae, 0 casks",
                                                  f"{self.host.ports_prefix}: 1 ports (1 active)"]))
        self.assertEqual([(r["name"], r["confidence"]) for r in data["brew"]["roots"]], [("wget", "EXACT")])
        self.assertEqual([t["key"] for t in data["ports"]["terms"]],
                         ["coverage", "unmigratable", "casks", "services", "undrivable", "work"])
        self.assertTrue(bundle.ports[0][2].closed)
        self.assertEqual(self.made[0].run_dir, self.calls[0]["run_dir"])

    def test_an_undrivable_source_manager_exits_1(self):
        self.both()
        self.host.formula("wget")
        mods = health_modules(ports=[issue("ports-platform-mismatch", self.host.ports_prefix)])
        self.assertEqual(self.run_command(self.host.bundle(), mods), recommend.EXIT_FINDINGS)
        self.assertIn(f"  Source manager undrivable: ports-platform-mismatch at {self.host.ports_prefix}",
                      self.stdout())

    def test_one_manager_exits_0_with_the_text(self):
        self.host.add_brew()
        self.host.formula("wget")
        mods = health_modules(brew=[issue("brew-broken-linkage", self.host.brew_prefix)])
        self.assertEqual(self.run_command(self.host.bundle(), mods, verbose=True), recommend.EXIT_OK)
        out = self.stdout()
        self.assertNotIn("Both managers present", out)
        self.assertIn("Term".ljust(len("Source manager undrivable  ")) + "target brew  target ports\n", out)
        self.assertIn(f"target brew: Homebrew at {self.host.brew_prefix}; sources none\n  Coverage: no roots\n", out)
        self.assertIn(f"  root wget ({self.host.brew_prefix}, installed on request): unmigratable (NONE): no MacPorts "
                      "catalogue to map against", out)
        self.assertTrue(out.endswith("Recommendation: target brew (Homebrew), 40.0 points against -10.1 for target "
                                     "ports; nothing to migrate in that direction.\n"), out)

    def test_the_text_names_both_managers_and_reuse(self):
        self.both()
        self.host.formula("wget")
        self.host.port("wget", "1.25.0", revision=1)
        self.assertEqual(self.run_command(self.host.bundle(), reused=True), recommend.EXIT_FINDINGS)
        out = self.stdout()
        self.assertTrue(out.startswith("recommend: reusing the scan of the last ten minutes (--rescan takes a fresh "
                                       "one)\nBoth managers present\n"
                                       f"  {self.host.brew_prefix}: 1 formulae, 0 casks\n"), out)
        self.assertEqual(self.calls[0]["rescan"], False)

    def test_rescan_asks_for_a_fresh_scan(self):
        self.host.add_brew()
        self.run_command(self.host.bundle(), rescan=True)
        self.assertEqual(self.calls[0]["rescan"], True)

    def test_a_medium_root_is_named_but_not_accepted(self):
        self.both()
        self.host.port("dd_rescue", "1.99.21", homepage="https://www.garloff.de/kurt/linux/ddrescue/")
        self.run_command(self.host.bundle(), verbose=True)
        self.assertIn(f"  root dd_rescue ({self.host.ports_prefix}, installed on request): formula ddrescue 1.29 "
                      "(MEDIUM), not accepted: canonical name: dd_rescue ~ ddrescue (ddrescue)\n", self.stdout())


class CliWiringTest(RecommendCase):
    """`recommend` through the real parser and the state lock"""

    def test_recommend_through_cli_main(self):
        self.both()
        self.host.formula("wget")
        self.host.formula("foo-bar")
        self.host.port("wget", "1.25.0", revision=1)
        obtain = mock.Mock(return_value=(self.host.bundle(), False))
        out = io.StringIO()
        with mock.patch.dict(cli.COMMANDS, {"recommend": recommend.cmd_recommend}), \
                mock.patch("brew_ports.system.running_as_root", return_value=False), \
                mock.patch("brew_ports.runner.command_runner", runner_factory([])), \
                mock.patch("brew_ports.scan.obtain", obtain), mock.patch.dict(sys.modules, health_modules()), \
                contextlib.redirect_stdout(out):
            code = cli.main(["--state-dir", self.path("s"), "recommend", "--json", "--rescan"],
                            environ=self.host.environ)
        self.assertEqual(code, recommend.EXIT_FINDINGS)
        self.assertEqual(json.loads(out.getvalue())["recommended"], "brew")
        self.assertTrue(obtain.call_args.kwargs["rescan"])


if __name__ == "__main__":
    unittest.main()

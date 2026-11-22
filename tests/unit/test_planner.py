"""`plan`: roles, options, questions, blocking, refusals, refresh and the files"""

import io
import json
import os
import unittest
from unittest import mock

from brew_ports import cli, model, plan_report, plan_sets, planner, report
from brew_ports.context import Context
from brew_ports.model import Blocks, Confidence, Manager, Severity
from brew_ports.runner import FakeResponse
from tests.unit.fixtures.planner.builders import (BREW, PORTS, FakeAsk, PlannerCase, World, actions, blocker, cask,
                                                  fake_runner, formula, options, port)
from tests.unit.helpers import make_instance, make_package


# Roles and the target choice --------------------------------------------------------------------

class RolesTest(PlannerCase):
    """The target choice, and every other instance as a source"""

    def test_homebrew_prefix_names_the_target(self):
        custom = self.path("Users", "alice", "homebrew")
        self.brew_source(formula("wget", self.usr_local))
        self.brew_target(prefix=custom)
        outcome = self.plan(target_prefix=None, environ={"HOMEBREW_PREFIX": custom})
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.target_prefix, custom)
        self.assertEqual(outcome.plan.source_prefixes, [self.usr_local])
        self.assertEqual(outcome.plan.removal_set, {self.usr_local: [("formula", "wget")]})

    def test_no_homebrew_target_without_homebrew_prefix(self):
        self.brew_source(formula("wget", self.usr_local))
        self.brew_target(prefix=self.path("Users", "alice", "homebrew"))
        outcome = self.plan(target_prefix=None)
        self.assert_exit(outcome, 3)
        self.assertIn("install Homebrew", self.text(outcome))
        self.assertEqual(outcome.result_file, "plan-refused.json")

    def test_missing_macports_names_bootstrap_ports(self):
        self.brew_source(formula("wget", self.usr_local))
        self.target = self.world.instances[0]
        outcome = self.plan(target=PORTS, target_prefix=None)
        self.assert_exit(outcome, 3)
        self.assertIn("brew-ports bootstrap-ports", self.text(outcome))

    def test_intel_macports_target_on_arm64_is_refused(self):
        self.ports_target(arch="x86_64")
        outcome = self.plan()
        self.assert_exit(outcome, 2)
        self.assertIn("x86_64", self.text(outcome))

    def test_undrivable_target_exits_3(self):
        self.ports_source(port("wget", self.local))
        self.brew_target(drivable=False)
        outcome = self.plan()
        self.assert_exit(outcome, 3)
        self.assertIn("cannot be driven", self.text(outcome))

    def test_every_other_instance_is_a_source(self):
        self.ports_source(port("wget", self.local))
        self.brew_source(formula("gnu-sed", self.usr_local))
        self.brew_target()
        plan = self.plan().plan
        self.assertEqual(sorted(plan.source_prefixes), sorted([self.local, self.usr_local]))
        self.assertEqual(len(plan.instances), 3)


# Options ------------------------------------------------------------------------------------------

class OptionsTest(PlannerCase):
    """The options from the command line, and their record in the plan"""

    def parse(self, *argv):
        """Parse a `plan` command line into its options

        @param argv  the arguments after `plan`
        @returns     the options
        """
        return planner.PlanOptions.from_args(cli.build_parser().parse_args(["plan"] + list(argv)))

    def test_from_args(self):
        opts = self.parse("--target", "ports", "--only", "a,b", "--only", "c", "--keep", "k", "--map", "x=y",
                          "--casks", "drop", "--remove-old=/usr/local,/opt/homebrew", "--accept-medium")
        self.assertEqual(opts.target, Manager.PORTS)
        self.assertEqual(opts.only, ["a", "b", "c"])
        self.assertEqual(opts.keep, ["k"])
        self.assertEqual(opts.maps, ["x=y"])
        self.assertEqual(opts.casks, "drop")
        self.assertEqual(opts.remove_manager, ["/usr/local", "/opt/homebrew"])
        self.assertTrue(opts.accept_medium)

    def test_comma_lists(self):
        self.assertEqual(planner._names(["a,b", " c "]), ["a", "b", "c"])
        self.assertEqual(planner._names(None), [])

    def test_bare_remove_manager_names_every_source(self):
        self.assertEqual(self.parse("--target", "brew", "--remove-old").remove_manager, [])
        self.assertIsNone(self.parse("--target", "brew").remove_manager)

    def test_casks_default_to_keep(self):
        opts = self.parse("--target", "brew")
        self.assertEqual(opts.cask_policy, "keep")
        self.assertIsNone(opts.casks)

    def test_plan_options_are_recorded_as_text(self):
        self.ports_source(port("wget", self.local))
        self.brew_target()
        plan = self.plan(start_services=True, only=["wget"]).plan
        self.assertEqual(plan.options["target"], "brew")
        self.assertEqual(plan.options["target_prefix"], self.target.prefix)
        self.assertEqual(plan.options["only"], "wget")
        self.assertEqual(plan.options["start_services"], "true")
        self.assertEqual(plan.options["casks"], "keep")
        self.assertEqual(plan.options["casks_explicit"], "false")
        self.assertEqual(plan.options["remove_manager"], "")


# Usage checks (exit 2) ------------------------------------------------------------------------------

class UsageTest(PlannerCase):
    """The usage errors that refuse a plan with exit 2"""

    def setUp(self):
        super().setUp()
        self.ports_source(port("wget", self.local), port("dd_rescue", self.local, "1.29"))
        self.brew_target()

    def test_an_unknown_keep_name_is_a_usage_error(self):
        outcome = self.plan(keep=["nosuch"])
        self.assert_exit(outcome, 2)
        self.assertIn("--keep nosuch: no source instance has nosuch installed", self.text(outcome))
        self.assertIsNone(outcome.draft)

    def test_keep_and_drop_of_one_name(self):
        self.assert_exit(self.plan(keep=["dd_rescue"], drop=["dd_rescue"]), 2)

    def test_drop_names_only_unmigratable_roots(self):
        outcome = self.plan(drop=["wget"])
        self.assert_exit(outcome, 2)
        self.assertIn("--drop wget", self.text(outcome))
        plan = self.plan(drop=["dd_rescue"]).plan
        self.assertIn(("port", "dd_rescue"), plan.removal_set[self.local])
        self.assertEqual([m.source.name for m in plan.unmigratable], ["dd_rescue"])

    def test_map_targets_must_be_in_the_catalogue(self):
        outcome = self.plan(maps=["dd_rescue=nosuch"])
        self.assert_exit(outcome, 2)
        self.assertIn("has no nosuch", self.text(outcome))
        self.assert_exit(self.plan(maps=["nothere=wget"]), 2)
        self.assert_exit(self.plan(maps=["broken"]), 2)

    def test_map_fixes_a_mapping(self):
        plan = self.plan(maps=["dd_rescue=ddrescue"]).plan
        mapping = next(m for m in plan.mappings if m.source.name == "dd_rescue")
        self.assertEqual((mapping.target_name, mapping.confidence), ("ddrescue", Confidence.EXACT))

    def test_remove_manager_refusals_in_their_order(self):
        self.assert_exit(self.plan(only=["wget"], remove_manager=[]), 2)
        self.assert_exit(self.plan(remove_manager=[self.target.prefix]), 2)
        self.assert_exit(self.plan(remove_manager=[self.path("nowhere")]), 2)


class RemoveManagerOrderTest(PlannerCase):
    """`--remove-old` of a Homebrew source: usage errors, then blocking findings, then refusals"""

    def setUp(self):
        super().setUp()
        self.brew_source(formula("wget", self.usr_local), formula("libfoo", self.usr_local),
                         cask("vlc", self.usr_local, homepage="https://www.videolan.org/vlc/"),
                         cask("zap", self.usr_local, privileged_uninstall=True))
        self.ports_target()

    def test_homebrew_source_needs_explicit_casks(self):
        outcome = self.plan(remove_manager=[self.usr_local])
        self.assert_exit(outcome, 2)
        self.assertIn("needs --casks drop or --casks map", self.text(outcome))

    def test_blocking_comes_before_the_refusals(self):
        issue = blocker("brew-degraded-inventory", self.usr_local, Blocks.TARGET, Blocks.CASKS, Blocks.REMOVE)
        outcome = self.plan(remove_manager=[self.usr_local], casks="drop", keep=["libfoo"], issues=[issue])
        self.assert_exit(outcome, 3)
        self.assertIn("blocked by brew-degraded-inventory", self.text(outcome))

    def test_kept_packages_and_manual_casks_refuse(self):
        outcome = self.plan(remove_manager=[self.usr_local], casks="drop", keep=["libfoo"])
        self.assert_exit(outcome, 1)
        text = self.text(outcome)
        self.assertIn(f"--remove-old {self.usr_local}: it keeps packages: libfoo", text)
        self.assertIn("it has manual casks", text)
        self.assertIn(f"{self.usr_local}/bin/brew uninstall --cask zap", text)


# Roots and the terminal questions ------------------------------------------------------------------

class QuestionsTest(PlannerCase):
    """The roots, and the terminal questions that settle them"""

    def setUp(self):
        super().setUp()
        self.ports_source(port("wget", self.local, "1.25.0"), port("libidn2", self.local, "2.3"),
                          port("dd_rescue", self.local, "1.29"), port("aria2", self.local, requested=None),
                          port("old", self.local, requested=False))
        self.brew_target()

    def test_defaults_without_a_terminal(self):
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual(sorted(p.name for p in plan.roots), ["aria2", "dd_rescue", "libidn2", "wget"])
        self.assertEqual([m.source.name for m in plan.mappings], ["wget"])
        self.assertEqual(sorted(m.source.name for m in plan.unmigratable), ["aria2", "dd_rescue", "libidn2"])
        self.assertEqual(sorted(p.name for p in plan.kept), ["aria2", "dd_rescue", "libidn2"])
        self.assertEqual(plan.removal_set, {self.local: [("port", "old"), ("port", "wget")]})

    def test_terminal_answers(self):
        ask = FakeAsk({"aria2": "no", "to replace it?": "yes", "libidn2": "drop"})
        plan = self.plan(ask=ask).plan
        self.assertEqual(sorted(m.source.name for m in plan.mappings), ["dd_rescue", "wget"])
        self.assertNotIn("aria2", [p.name for p in plan.roots])
        self.assertEqual(plan.removal_set[self.local], [("port", "aria2"), ("port", "dd_rescue"), ("port", "libidn2"),
                                                        ("port", "old"), ("port", "wget")])
        self.assertTrue(any("whether you installed it yourself" in q for q in ask.asked))
        self.assertTrue(any("no replacement in Homebrew" in q for q in ask.asked))

    def test_yes_takes_every_default(self):
        ask = FakeAsk({"to replace it?": "yes", "libidn2": "drop"}, yes=True)
        plan = self.plan(ask=ask).plan
        self.assertEqual([m.source.name for m in plan.mappings], ["wget"])

    def test_accept_medium_asks_no_question(self):
        ask = FakeAsk()
        plan = self.plan(ask=ask, accept_medium=True).plan
        self.assertIn("dd_rescue", [m.source.name for m in plan.mappings])
        self.assertFalse(any("to replace it?" in q for q in ask.asked))

    def test_the_overview_comes_first_and_questions_name_both_sides(self):
        ask = FakeAsk({"aria2": "no", "to replace it?": "yes", "libidn2": "drop"})
        self.plan(ask=ask)
        self.assertTrue(ask.asked[0].startswith("Moving packages into Homebrew"))
        self.assertIn(f"\n  from MacPorts 2.12.7 at {self.local}", ask.asked[0])
        self.assertFalse(any("Moving packages into" in q for q in ask.asked[1:]))
        medium = next(q for q in ask.asked if "to replace it?" in q)
        self.assertIn(f"dd_rescue 1.29 (MacPorts at {self.local}): Homebrew has no exact match.", medium)
        self.assertTrue(medium.endswith(f"into {self.target.prefix} to replace it?"))

    def test_keeping_a_package_says_it_stops_remove_old(self):
        ask = FakeAsk({"aria2": "no", "to replace it?": "yes"})
        self.plan(ask=ask, remove_manager=[self.local])
        question = next(q for q in ask.asked if "libidn2" in q)
        self.assertIn(f"Keeping it stops --remove-old from uninstalling MacPorts at {self.local}.", question)

    def test_a_dropped_root_is_not_asked_about(self):
        ask = FakeAsk()
        plan = self.plan(ask=ask, drop=["dd_rescue", "libidn2"]).plan
        self.assertFalse(any("dd_rescue" in q or "libidn2" in q for q in ask.asked))
        self.assertIn(("port", "libidn2"), plan.removal_set[self.local])

    def test_a_kept_root_gets_no_mapping_and_no_install(self):
        plan = self.plan(keep=["wget"]).plan
        self.assertEqual(plan.mappings, [])
        self.assertIn("wget", [p.name for p in plan.kept])
        self.assertIn("wget", [p.name for p in plan.roots])
        self.assertEqual(actions(plan, 3), [])

    def test_interpreter_extras_make_a_root(self):
        self.world.packages.append(port("python313", self.local, "3.13.18", requested=False))
        self.world.extras = {"python": [{"version": "3.13", "instance_prefix": self.local, "location": "prefix",
                                         "site_packages": self.local + "/site-packages",
                                         "dists": [{"name": "requests", "version": "2.0"}], "scripts": []}]}
        plan = self.plan().plan
        self.assertIn("python313", [p.name for p in plan.roots])
        self.assertEqual(next(m for m in plan.mappings if m.source.name == "python313").target_name, "python@3.13")


# Blocking findings (exit 3) ---------------------------------------------------------------------------

class BlockingTest(PlannerCase):
    """The findings that block a plan with exit 3, by what they block"""

    def setUp(self):
        super().setUp()
        self.brew_source(formula("wget", self.usr_local), cask("vlc", self.usr_local))
        self.ports_source(port("gsed", self.local, "4.9"))
        self.brew_target()

    def blocked(self, issue, **kw):
        """Plan the host with one finding

        @param issue  the finding
        @param kw     the plan's options
        @returns      the outcome
        """
        return self.plan(issues=[issue], **kw)

    def test_any(self):
        outcome = self.blocked(blocker("system-clt-missing", None, Blocks.ANY))
        self.assert_exit(outcome, 3)
        self.assertIsNone(outcome.draft)
        with open(outcome.path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["refused"]["exit"], 3)
        self.assertEqual(data["refused"]["blocking"][0]["code"], "system-clt-missing")

    def test_critical_always(self):
        self.assert_exit(self.blocked(blocker("ports-registry-busy", self.local, severity=Severity.CRITICAL)), 3)

    def test_target(self):
        self.assert_exit(self.blocked(blocker("brew-unwritable-prefix", self.target.prefix, Blocks.TARGET)), 3)
        self.assert_exit(self.blocked(blocker("ports-registry-schema-update", self.local, Blocks.TARGET)), 0)

    def test_uninstall(self):
        issue = blocker("brew-unwritable-prefix", self.usr_local, Blocks.TARGET, Blocks.UNINSTALL)
        self.assert_exit(self.blocked(issue), 3)
        self.assert_exit(self.blocked(issue, keep=["wget", "vlc"]), 0)

    def test_casks(self):
        issue = blocker("brew-degraded-inventory", self.usr_local, Blocks.TARGET, Blocks.CASKS, Blocks.REMOVE)
        self.assert_exit(self.blocked(issue), 3)       # the brew target adopts vlc, which drops the source's record
        self.assert_exit(self.blocked(issue, keep=["vlc"]), 0)

    def test_remove(self):
        issue = blocker("ports-damaged-registry", self.local, Blocks.TARGET, Blocks.REMOVE)
        self.assert_exit(self.blocked(issue), 0)
        outcome = self.blocked(issue, remove_manager=[self.local])
        self.assert_exit(outcome, 3)
        self.assertIn("blocked by ports-damaged-registry", self.text(outcome))

    def test_blocking_comes_before_the_questions(self):
        self.world.packages.append(port("aria2", self.local, requested=None))
        ask = FakeAsk()
        self.assert_exit(self.plan(ask=ask, issues=[blocker("system-clt-missing", None, Blocks.ANY)]), 3)
        self.assertEqual(ask.asked, [])


class DegradedInventoryTest(PlannerCase):
    """A Homebrew source whose inventory is degraded, under each cask policy"""

    def setUp(self):
        super().setUp()
        self.brew_source(formula("wget", self.usr_local), cask("vlc", self.usr_local),
                         inventory_error="brew info failed")
        self.ports_target()
        self.issue = blocker("brew-degraded-inventory", self.usr_local, Blocks.TARGET, Blocks.CASKS, Blocks.REMOVE)

    def test_casks_drop_is_blocked(self):
        outcome = self.plan(casks="drop", issues=[self.issue])
        self.assert_exit(outcome, 3)
        self.assertIn("blocked by brew-degraded-inventory", self.text(outcome))

    def test_casks_keep_passes(self):
        outcome = self.plan(issues=[self.issue])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.removal_set, {self.usr_local: [("formula", "wget")]})


# Refresh -----------------------------------------------------------------------------------------------

class RefreshTest(PlannerCase):
    """`plan --refresh`: the first pass, the question, the refresh and the fresh scan"""

    def setUp(self):
        super().setUp()
        self.ports_source(port("wget", self.local))
        self.brew_target()

    def update_argv(self):
        """Return the argv of the target's `brew update`

        @returns  the argv under `arch -arm64`
        """
        return ("/usr/bin/arch", "-arm64", self.target.binary, "update")

    def refresh(self, ask, issues=(), responses=None):
        """Plan with `--refresh`, the fresh scan and its write stubbed

        @param ask        answers the terminal questions
        @param issues     the findings
        @param responses  the runner's answers to known commands, by argv
        @returns          the outcome, the runner and the stub of `scan.build`
        """
        run_dir = self.sd.new_run()
        runner = fake_runner(run_dir, responses=responses)
        bundle = self.world.bundle()
        fresh = self.world.bundle()
        with mock.patch("brew_ports.doctor.detect_all", return_value=list(issues)), \
                mock.patch("brew_ports.scan.build", return_value=fresh) as build, \
                mock.patch("brew_ports.scan.write"):
            outcome = planner.build(bundle, options(BREW, self.target.prefix, refresh=True, dry_run=False),
                                    runner, ask=ask, state_dir=self.sd, run_dir=run_dir)
        return outcome, runner, build

    def test_blocking_findings_stop_the_refresh(self):
        issue = blocker("system-clt-missing", None, Blocks.ANY)
        outcome, runner, build = self.refresh(FakeAsk(yes=True), issues=[issue])
        self.assert_exit(outcome, 3)
        self.assertEqual(runner.calls, [])
        self.assertIsNone(self.sd.dirty())
        build.assert_not_called()

    def test_refresh_runs_brew_update_and_rescans(self):
        outcome, runner, build = self.refresh(FakeAsk(yes=True), responses={self.update_argv(): FakeResponse()})
        self.assert_exit(outcome, 0)
        self.assertIn(self.update_argv(), runner.calls)
        self.assertEqual(self.sd.dirty()["command"], "plan --refresh")
        build.assert_called_once()
        self.assertIn("refreshed: planned against a fresh inventory", outcome.report)

    def test_declined_refresh_runs_nothing(self):
        outcome, runner, build = self.refresh(FakeAsk(confirm_answer=False))
        self.assert_exit(outcome, 0)
        self.assertEqual(runner.calls, [])
        self.assertIsNone(self.sd.dirty())
        build.assert_not_called()

    def test_a_failed_refresh_exits_4(self):
        outcome, _, _ = self.refresh(FakeAsk(yes=True))
        self.assert_exit(outcome, 4)
        self.assertEqual(outcome.result_file, "plan-refused.json")

    def test_dry_run_only_prints_the_commands(self):
        run_dir = self.sd.new_run()
        runner = fake_runner(run_dir)
        with mock.patch("brew_ports.doctor.detect_all", return_value=[]):
            outcome = planner.build(self.world.bundle(), options(BREW, self.target.prefix, refresh=True,
                                                                 dry_run=True),
                                    runner, ask=FakeAsk(yes=True), state_dir=self.sd, run_dir=run_dir)
        self.assert_exit(outcome, 0)
        self.assertEqual(runner.calls, [])
        self.assertTrue(any(line.startswith("would run: ") and "update" in line for line in outcome.report))

    def test_a_macports_target_needs_sudo_and_syncs(self):
        self.world = World()
        self.brew_source(formula("wget", self.usr_local))
        self.ports_target()
        argv = ("/usr/bin/sudo", "-n", "--", "/usr/bin/arch", "-arm64", self.target.binary, "-N", "sync")
        run_dir = self.sd.new_run()
        runner = fake_runner(run_dir, responses={argv: FakeResponse()})
        with mock.patch("brew_ports.doctor.detect_all", return_value=[]), \
                mock.patch("brew_ports.scan.build", return_value=self.world.bundle()), \
                mock.patch("brew_ports.scan.write"):
            outcome = planner.build(self.world.bundle(), options(PORTS, self.target.prefix, refresh=True),
                                    runner, ask=FakeAsk(yes=True), state_dir=self.sd, run_dir=run_dir)
        self.assert_exit(outcome, 0)
        self.assertTrue(runner.sudo_ready)
        self.assertIn(argv, runner.calls)


# Files ---------------------------------------------------------------------------------------------------

class FilesTest(PlannerCase):
    """`plan.json`, `plan-refused.json` and the `--out` copy"""

    def setUp(self):
        super().setUp()
        self.ports_source(port("wget", self.local, "1.25.0", deps=["gsed"]),
                          port("gsed", self.local, "4.9", requested=False))
        self.brew_target()

    def test_plan_json_round_trips(self):
        outcome = self.plan(out=self.path("copy.json"))
        self.assert_exit(outcome, 0)
        with open(outcome.path, encoding="utf-8") as fh:
            text = fh.read()
        back = model.from_json(model.Plan, text)
        self.assertEqual(model.to_plain(back), model.to_plain(outcome.plan))
        self.assertIsInstance(back.removal_set[self.local][0], tuple)
        self.assertIs(back.target, Manager.BREW)
        self.assertIs(back.mappings[0].confidence, Confidence.EXACT)
        self.assertEqual([p.number for p in back.phases], [0, 1, 2, 3, 4, 5, 7, 8])
        with open(self.path("copy.json"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), text)
        self.assertEqual(os.path.basename(outcome.path), "plan.json")

    def test_refused_plan_is_written_and_copied(self):
        outcome = self.plan(only=["gsed"], out=self.path("copy.json"))
        self.assert_exit(outcome, 1)
        self.assertIsNone(outcome.plan)
        self.assertIsNotNone(outcome.draft)
        self.assertEqual(os.path.basename(outcome.path), "plan-refused.json")
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(outcome.path), "plan.json")))
        with open(self.path("copy.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["refused"]["exit"], 1)
        self.assertTrue(any("is needed by port wget" in r for r in data["refused"]["reasons"]))
        self.assertEqual(data["plan"]["removal_set"], {self.local: [["port", "gsed"]]})
        with self.assertRaises(TypeError):
            model.from_dict(model.Plan, data)


class CommandTest(PlannerCase):
    """`brew-ports plan` from the command line to the printed report"""

    def test_cmd_plan_prints_the_report(self):
        self.ports_source(port("wget", self.local))
        self.brew_target()
        args = cli.build_parser().parse_args(["plan", "--target", "brew", "--target-prefix", self.target.prefix])
        console = report.Console(stream=io.StringIO(), err=io.StringIO())
        ctx = Context(args, console, self.sd, tty=False, environ={"HOME": "/Users/alice"})
        with mock.patch("brew_ports.scan.obtain", return_value=(self.world.bundle(), False)), \
                mock.patch("brew_ports.doctor.detect_all", return_value=[]):
            code = planner.cmd_plan(ctx, make_runner=lambda c, r: fake_runner(r))
        self.assertEqual(code, 0)
        out = console.stream.getvalue()
        self.assertIn("plan written: ", out)
        self.assertIn("wget", out)


class PlanWordsTest(unittest.TestCase):
    """The plain words of the plan's overview and of its questions"""

    def setUp(self):
        self.target = make_instance(BREW, "/opt/homebrew", version="5.0.2")
        self.ports = make_instance(PORTS, "/opt/local", version="2.10.5")
        self.intel = make_instance(BREW, "/usr/local", version="4.6.0", arch="x86_64")

    def unit(self, name: str, version: str) -> plan_sets.Unit:
        """Return the unit of a MacPorts port at `/opt/local`

        @param name     the port
        @param version  its version as MacPorts records it
        @returns        the unit
        """
        return plan_sets.units_of(self.ports, [make_package(name, "port", "/opt/local", version=version)])[0]

    @staticmethod
    def mapping(unit: plan_sets.Unit, name: str, version: str, evidence: tuple[str, ...] = ()) -> model.Mapping:
        """Return a MEDIUM mapping of a unit to a formula

        @param unit      the source unit
        @param name      the formula
        @param version   its catalogue version
        @param evidence  the matcher's evidence lines
        @returns         the mapping
        """
        return model.Mapping(source=unit.pkg, target_kind="formula", target_name=name, target_version=version,
                             confidence=Confidence.MEDIUM, evidence=list(evidence), companions=[], selections=[],
                             variants_note=None)

    def test_the_overview_names_every_installation_and_the_removals(self):
        self.assertEqual(plan_report.overview(self.target, [self.ports, self.intel], [self.ports, self.intel]), [
            "Moving packages into Homebrew 5.0.2 at /opt/homebrew (Apple Silicon)",
            "  from MacPorts 2.10.5 at /opt/local (Apple Silicon)",
            "  from Homebrew 4.6.0 at /usr/local (Intel)",
            "  then uninstalling MacPorts at /opt/local and Homebrew at /usr/local"])

    def test_an_installation_that_cannot_be_driven_says_so(self):
        broken = make_instance(PORTS, "/opt/local", version=None, arch=None, drivable=False,
                               usability=model.Usability.NO_REGISTRY)
        self.assertEqual(plan_report.place(broken), "MacPorts at /opt/local (cannot be driven: no-registry)")

    def test_a_major_version_jump_is_said_in_plain_words(self):
        unit = self.unit("giflib", "4.2.3_0")
        self.assertEqual(plan_report.medium_question(unit, self.mapping(unit, "giflib", "5.2.2"), self.target),
                         "giflib 4.2.3 (MacPorts at /opt/local): Homebrew has no exact match. The closest is formula "
                         "giflib 5.2.2: a newer major version, so programs built against 4.x may not work with it.\n"
                         "Install giflib 5.2.2 into /opt/homebrew to replace it?")

    def test_another_name_or_else_the_evidence_says_how_it_differs(self):
        unit = self.unit("dd_rescue", "1.29")
        self.assertIn("formula ddrescue 1.30: another name, for what looks like the same software.",
                      plan_report.medium_question(unit, self.mapping(unit, "ddrescue", "1.30"), self.target))
        unit = self.unit("foo", "1.2")
        line = "version: foo and foo2 share the source's major; foo is the newest"
        self.assertIn(f"formula foo 1.3: {line}.",
                      plan_report.medium_question(unit, self.mapping(unit, "foo", "1.3", (line,)), self.target))

    def test_keeping_a_package_names_the_installation_it_keeps(self):
        unit = self.unit("zlib", "1.3")
        self.assertEqual(plan_report.unmigratable_question(unit, "no equivalent", self.target, True).splitlines(), [
            "zlib 1.3 (MacPorts at /opt/local): no replacement in Homebrew (no equivalent).",
            "Keeping it stops --remove-old from uninstalling MacPorts at /opt/local.",
            "Keep it in MacPorts, or drop it (uninstall it with no replacement)?"])


if __name__ == "__main__":
    unittest.main()

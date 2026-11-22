"""`plan`: roles, options, questions, blocking, refusals, refresh, the files and the report"""

import contextlib
import io
import json
import os
import unittest
from typing import Any
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
        custom = self.path("Users", "alice", "homebrew")
        self.brew_source(formula("wget", self.usr_local))
        self.brew_target(prefix=custom)
        outcome = self.plan(target_prefix=None)
        self.assert_exit(outcome, 3)
        both = f"Homebrew 7.0.11 at {self.usr_local} (Apple Silicon) and Homebrew 7.0.11 at {custom} (Apple Silicon)"
        self.assertEqual(outcome.problems[0], (
            f"brew-ports: this Mac has no Homebrew at /opt/homebrew. It has {both}: say which one the packages move "
            "into with --target-prefix, or install Homebrew at the usual place (https://brew.sh)"))
        self.assertEqual(outcome.report, [])
        self.assertEqual(outcome.result_file, "plan-refused.json")

    def test_the_only_homebrew_elsewhere_is_named_with_its_option(self):
        self.ports_source(port("wget", self.local))
        self.brew_target(prefix=self.usr_local)
        outcome = self.plan(target_prefix=None)
        self.assert_exit(outcome, 3)
        self.assertEqual(outcome.problems[0], (
            f"brew-ports: this Mac has no Homebrew at /opt/homebrew, only Homebrew 7.0.11 at {self.usr_local} "
            f"(Apple Silicon). To move the packages into that one, plan with --target-prefix {self.usr_local}, or "
            "install Homebrew at the usual place (https://brew.sh)"))

    def test_one_installation_alone_has_nothing_to_move(self):
        self.brew_target()
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.report, [
            f"This Mac has only Homebrew 7.0.11 at {self.target.prefix} (Apple Silicon): there is nothing to move."])
        self.assertEqual((outcome.problems, outcome.plan, outcome.result_file), ([], None, None))

    def test_missing_macports_names_bootstrap_ports(self):
        self.brew_source(formula("wget", self.usr_local))
        self.target = self.world.instances[0]
        outcome = self.plan(target=PORTS, target_prefix=None)
        self.assert_exit(outcome, 3)
        self.assertEqual(outcome.problems[0], "brew-ports: MacPorts is not installed. Run `brew-ports "
                                              "bootstrap-ports`, then plan again")

    def test_intel_macports_target_on_arm64_is_refused(self):
        self.ports_target(arch="x86_64")
        outcome = self.plan()
        self.assert_exit(outcome, 2)
        self.assertEqual(outcome.problems, [
            f"brew-ports: --target-prefix: MacPorts at {self.local} is an Intel installation on an Apple Silicon "
            "Mac, and ports cannot be built for it. Choose another --target-prefix"])

    def test_undrivable_target_exits_3(self):
        self.ports_source(port("wget", self.local))
        self.brew_target(drivable=False)
        outcome = self.plan()
        self.assert_exit(outcome, 3)
        self.assertEqual(outcome.problems[0], f"brew-ports: nothing can move into Homebrew at {self.target.prefix}: "
                                              "its `brew` command cannot run. `brew-ports doctor` shows the fix")

    def test_a_long_error_of_the_target_gives_its_first_line_only(self):
        self.ports_source(port("wget", self.local))
        self.brew_target(drivable=False)
        self.target.usability_detail = "brew config failed with exit 1:\nError: line 2\nError: line 3"
        outcome = self.plan()
        self.assertEqual(outcome.problems[0], (
            f"brew-ports: nothing can move into Homebrew at {self.target.prefix}: its `brew` command cannot run "
            "(brew config failed with exit 1). `brew-ports doctor` shows the fix"))

    def test_a_wrong_target_prefix_says_what_this_mac_has(self):
        self.ports_source(port("wget", self.local))
        self.brew_target()
        nowhere = self.path("nowhere")
        outcome = self.plan(target_prefix=nowhere)
        self.assert_exit(outcome, 3)
        self.assertEqual(outcome.problems[0], (
            f"brew-ports: there is no Homebrew at {nowhere}: this Mac has Homebrew at {self.target.prefix}"))
        outcome = self.plan(target=PORTS, target_prefix=nowhere)
        self.assertEqual(outcome.problems[0], (
            f"brew-ports: there is no MacPorts at {nowhere}: this Mac has MacPorts at {self.local}"))

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

    def rejected(self, *argv):
        """Parse a `plan` command line that the parser refuses, its usage text kept off the test's output

        @param argv  the arguments after `plan`
        @returns     the exit code the parser leaves with
        """
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            self.parse(*argv)
        return caught.exception.code

    def test_from_args(self):
        opts = self.parse("--target", "ports", "--only", "a,b", "--only", "c", "--leave", "k", "--uninstall", "u,v",
                          "--replace", "x=y", "--casks", "uninstall", "--accept-closest", "--pipx")
        self.assertEqual(opts.target, Manager.PORTS)
        self.assertEqual(opts.only, ["a", "b", "c"])
        self.assertEqual(opts.keep, ["k"])
        self.assertEqual(opts.drop, ["u", "v"])
        self.assertEqual(opts.maps, ["x=y"])
        self.assertEqual(opts.casks, "drop")
        self.assertTrue(opts.accept_medium)
        self.assertEqual(opts.lang_packages, "pipx")
        self.assertEqual(self.parse("--target", "ports").lang_packages, "report")
        self.assertEqual(self.parse("--target", "ports", "--casks", "replace").casks, "map")
        self.assertEqual(self.parse("--target", "ports", "--casks", "keep").casks, "keep")

    def test_comma_lists(self):
        self.assertEqual(planner.split_names(["a,b", " c "]), ["a", "b", "c"])
        self.assertEqual(planner.split_names(None), [])
        self.assertEqual(planner.split_names(["", " , "]), [])

    def test_delete_takes_paths_and_keep_managers_is_a_flag(self):
        opts = self.parse("--target", "brew", "--delete", "/usr/local,/opt/local", "--delete", "/opt/other")
        self.assertEqual(opts.delete, ["/usr/local", "/opt/local", "/opt/other"])
        self.assertTrue(self.parse("--target", "brew", "--keep-managers").keep_managers)
        plain = self.parse("--target", "brew")
        self.assertEqual((plain.delete, plain.keep_managers), ([], False))

    def test_the_target_takes_either_name_of_a_manager(self):
        self.assertEqual(self.parse("--target", "homebrew").target, Manager.BREW)
        self.assertEqual(self.parse("--target", "MacPorts").target, Manager.PORTS)

    def test_the_parser_rejects_options_it_does_not_have(self):
        for argv in (["--remove-old"], ["--keep", "x"], ["--accept-medium"], ["--dry-run"], ["--drop", "x"],
                     ["--map", "a=b"], ["--lang-packages", "pipx"], ["--no-color"], ["--casks", "drop"],
                     ["--casks", "map"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.rejected("--target", "brew", *argv), 2)

    def test_an_option_is_not_taken_by_its_first_letters(self):
        for argv in (["--keep"], ["--accept"], ["--del", "/opt/local"], ["--uninst", "x"], ["--start"], ["--ref"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.rejected("--target", "brew", *argv), 2)
        self.assertEqual(self.rejected("--targ", "brew"), 2)

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
        self.assertEqual(plan.options["keep_managers"], "false")
        self.assertEqual(plan.options["delete"], "")
        self.assertNotIn("dry_run", plan.options)


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
        self.assertEqual(outcome.problems, [
            f"brew-ports: --leave nosuch: no package named nosuch is installed in MacPorts at {self.local}"])
        self.assertEqual(outcome.report, [])
        self.assertIsNone(outcome.draft)

    def test_keep_and_drop_of_one_name(self):
        outcome = self.plan(keep=["dd_rescue"], drop=["dd_rescue"])
        self.assert_exit(outcome, 2)
        self.assertIn("brew-ports: dd_rescue is named in both --leave and --uninstall", outcome.problems)

    def test_drop_names_only_unmigratable_roots(self):
        outcome = self.plan(drop=["wget"])
        self.assert_exit(outcome, 2)
        self.assertEqual(outcome.problems, [
            "brew-ports: --uninstall wget: wget has a replacement and moves. To leave it where it is, plan with "
            "`--leave wget`"])
        self.world.packages.append(port("libidn2", self.local, requested=False))
        for options_, why in (({}, "libidn2 is a dependency: the move uninstalls it once nothing that stays needs it"),
                              ({"only": ["wget"]}, "libidn2 is not among the packages --only names")):
            with self.subTest(options=options_):
                outcome = self.plan(drop=["libidn2"], **options_)
                self.assert_exit(outcome, 2)
                self.assertEqual(outcome.problems, [f"brew-ports: --uninstall libidn2: {why}"])
        plan = self.plan(drop=["dd_rescue"]).plan
        self.assertIn(("port", "dd_rescue"), plan.removal_set[self.local])
        self.assertEqual([m.source.name for m in plan.unmigratable], ["dd_rescue"])

    def test_map_targets_must_be_in_the_catalogue(self):
        outcome = self.plan(maps=["dd_rescue=nosuch"])
        self.assert_exit(outcome, 2)
        self.assertEqual(outcome.problems, [
            "brew-ports: --replace dd_rescue=nosuch: Homebrew's package list has no nosuch"])
        unknown = self.plan(maps=["nothere=wget"])
        self.assert_exit(unknown, 2)
        self.assertEqual(unknown.problems, [
            f"brew-ports: --replace nothere: no package named nothere is installed in MacPorts at {self.local}"])
        broken = self.plan(maps=["broken"])
        self.assert_exit(broken, 2)
        self.assertEqual(broken.problems, ["brew-ports: --replace wants OLD=NEW, not 'broken'"])

    def test_map_fixes_a_mapping(self):
        plan = self.plan(maps=["dd_rescue=ddrescue"]).plan
        mapping = next(m for m in plan.mappings if m.source.name == "dd_rescue")
        self.assertEqual((mapping.target_name, mapping.confidence), ("ddrescue", Confidence.EXACT))

    def test_delete_is_a_usage_error_with_only_or_a_wrong_path(self):
        self.unmark(self.local)
        unmarked = self.plan(delete=[self.local])
        self.assert_exit(unmarked, 2)
        self.assertEqual(unmarked.problems, [
            f"brew-ports: --delete {self.local}: {self.local} has no etc/macports/macports.conf, so it does not look "
            "like MacPorts, and brew-ports deletes no folder that it cannot tell is a manager's"])
        self.mark(self.local)
        outcome = self.plan(only=["wget"], delete=[self.local])
        self.assert_exit(outcome, 2)
        self.assertEqual(outcome.problems, [f"brew-ports: {planner.ONLY_DELETES_NOTHING}"])
        outcome = self.plan(delete=[self.target.prefix])
        self.assert_exit(outcome, 2)
        self.assertEqual(outcome.problems, [
            f"brew-ports: --delete {self.target.prefix}: that is where the packages move to"])
        outcome = self.plan(delete=[self.path("nowhere")])
        self.assert_exit(outcome, 2)
        self.assertEqual(outcome.problems, [
            f"brew-ports: --delete {self.path('nowhere')}: there is no Homebrew or MacPorts there"])

    def test_a_replace_name_matches_a_port_in_any_case(self):
        plan = self.plan(maps=["DD_Rescue=ddrescue"]).plan
        mapping = next(m for m in plan.mappings if m.source.name == "dd_rescue")
        self.assertEqual((mapping.target_name, mapping.confidence), ("ddrescue", Confidence.EXACT))

    def test_casks_is_a_usage_error_for_a_move_into_homebrew(self):
        outcome = self.plan(casks="drop")
        self.assert_exit(outcome, 2)
        self.assertEqual(outcome.problems, [
            "brew-ports: --casks is for a move into MacPorts (--target ports). Into Homebrew, apps stay where they are "
            "and the Homebrew they move into takes over their record"])

    def test_an_out_file_that_cannot_be_written_is_refused_first(self):
        ask = FakeAsk()
        for out, why in ((self.path("missing", "plan.json"), f"the folder {self.path('missing')} does not exist"),
                         (self.tmp, "that is a folder. Name the file the plan is saved as")):
            with self.subTest(out=out):
                outcome = self.plan(ask=ask, out=out)
                self.assert_exit(outcome, 2)
                self.assertEqual(outcome.problems, [f"brew-ports: --out {out}: {why}"])
        self.assertEqual(ask.asked, [])


class RemoveManagerOrderTest(PlannerCase):
    """A Homebrew source of a MacPorts target: what keeps it, then blocking findings, then refusals"""

    def setUp(self):
        super().setUp()
        self.brew_source(formula("wget", self.usr_local), formula("libfoo", self.usr_local),
                         cask("vlc", self.usr_local, homepage="https://www.videolan.org/vlc/"),
                         cask("zap", self.usr_local, privileged_uninstall=True))
        self.ports_target()

    def test_the_default_casks_keep_homebrew_installed(self):
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertIn(f"  Homebrew at {self.usr_local} stays installed, because it keeps vlc, zap", outcome.report)
        self.assertNotIn(6, [p.number for p in outcome.plan.phases])
        self.assertEqual(outcome.plan.options["remove_manager"], "")
        title = f"Staying in Homebrew at {self.usr_local}"
        self.assertEqual(self.section(outcome, title), [
            title, f"  2 packages: {plan_sets.KEPT_APP}", "      vlc 1.0, zap 1.0"])

    def test_a_long_group_that_stays_is_cut_and_whole_in_verbose(self):
        self.world.packages += [cask(f"app{n}", self.usr_local) for n in range(9)]
        cut = self.section(self.plan(), f"Staying in Homebrew at {self.usr_local}")
        self.assertEqual(cut[1:], [
            f"  11 packages: {plan_sets.KEPT_APP}",
            "      app0 1.0, app1 1.0, app2 1.0, app3 1.0, app4 1.0, app5 1.0, app6 1.0, app7 1.0 and 3 more "
            "(--verbose lists all)"])
        whole = self.section(self.plan(verbose=True), f"Staying in Homebrew at {self.usr_local}")
        self.assertTrue(whole[2].endswith("app7 1.0, app8 1.0, vlc 1.0, zap 1.0"), whole[2])

    def test_blocking_comes_before_the_refusals(self):
        issue = blocker("brew-degraded-inventory", self.usr_local, Blocks.TARGET, Blocks.CASKS, Blocks.REMOVE)
        outcome = self.plan(delete=[self.usr_local], casks="drop", keep=["libfoo"], issues=[issue])
        self.assert_exit(outcome, 3)
        self.assertEqual(outcome.problems[:2], [
            f"brew-ports: this stops the move: finding brew-degraded-inventory ({self.usr_local})", "    evidence"])

    def test_kept_packages_and_manual_casks_refuse(self):
        kept = self.plan(delete=[self.usr_local], casks="drop", keep=["libfoo"])
        self.assert_exit(kept, 1)
        refused = f"    --delete {self.usr_local}: Homebrew at {self.usr_local} cannot be deleted while "
        held = "it holds zap, which only you can uninstall "
        command = f"(`{self.usr_local}/bin/brew uninstall --cask zap`, then plan again)"
        settle = ". Settle what stays in it, or plan without --delete"
        self.assertIn(f"{refused}it keeps libfoo and {held}{command}{settle}", kept.problems)
        self.assertIn(f"  {self.usr_local}/bin/brew uninstall --cask zap", kept.report)
        manual = self.plan(delete=[self.usr_local], casks="drop")
        self.assert_exit(manual, 1)
        self.assertIn(refused + held + command + settle, manual.problems)
        with self.subTest("the overview agrees with the refusal: the installation that keeps libfoo is not empty"):
            self.assertEqual(kept.report[2], f"  Homebrew at {self.usr_local} stays installed although --delete names "
                                             f"it: it keeps libfoo and {held}(the command is below)")
        with self.subTest("vlc and wget are both packages the user installed: no uninstall is a dependency"):
            self.assertNotIn("dependency", self.section(kept, f"To uninstall from Homebrew at {self.usr_local}")[1])


# The old installations a plan uninstalls after the move ---------------------------------------------

class OldInstallationsTest(PlannerCase):
    """Which old installations a plan uninstalls once their packages have moved"""

    def setUp(self):
        super().setUp()
        self.ports_source(port("wget", self.local, "1.25.0"), port("gsed", self.local, "4.9"))
        self.brew_target()

    def phases(self, outcome):
        """Return the numbers of a plan's phases

        @param outcome  the outcome of a plan that was made
        @returns        the numbers, in order
        """
        return [phase.number for phase in outcome.plan.phases]

    def test_a_full_move_uninstalls_the_installation_it_empties(self):
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.options["remove_manager"], self.local)
        self.assertIn(6, self.phases(outcome))
        self.assertIn(f"  then uninstalling MacPorts at {self.local}, which will be empty", outcome.report)

    def test_a_package_that_stays_keeps_its_installation(self):
        outcome = self.plan(keep=["gsed"])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.options["remove_manager"], "")
        self.assertNotIn(6, self.phases(outcome))
        self.assertIn(f"  MacPorts at {self.local} stays installed, because it keeps gsed", outcome.report)
        self.assertEqual(outcome.plan.removal_set, {self.local: [("port", "wget")]})

    def test_keep_managers_uninstalls_no_installation(self):
        outcome = self.plan(keep_managers=True)
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.options["remove_manager"], "")
        self.assertEqual(outcome.plan.options["keep_managers"], "true")
        self.assertNotIn(6, self.phases(outcome))
        self.assertIn(f"  MacPorts at {self.local} stays installed, as you asked (--keep-managers)", outcome.report)
        self.assertEqual(outcome.plan.removal_set, {self.local: [("port", "gsed"), ("port", "wget")]})

    def test_only_uninstalls_no_installation(self):
        outcome = self.plan(only=["wget"])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.options["remove_manager"], "")
        self.assertNotIn(6, self.phases(outcome))
        self.assertEqual(outcome.report[:3], [
            f"Moving 1 package into Homebrew 7.0.11 at {self.target.prefix} (Apple Silicon)",
            f"  from MacPorts 2.12.7 at {self.local} (Apple Silicon), which stays installed: 2 ports", ""])

    def test_delete_takes_an_installation_whose_command_cannot_run(self):
        self.brew_source(formula("gnu-tar", self.usr_local), drivable=False)
        left = self.plan()
        self.assert_exit(left, 0)
        self.assertEqual([p.name for p in left.plan.left_in_place], ["gnu-tar"])
        self.assertEqual(left.plan.options["remove_manager"], self.local)
        outcome = self.plan(delete=[self.usr_local])
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual(plan.path_removed, {self.usr_local: [("formula", "gnu-tar")]})
        self.assertEqual(plan.left_in_place, [])
        self.assertIn(6, self.phases(outcome))
        self.assertEqual(plan.options["remove_manager"], f"{self.local},{self.usr_local}")
        self.assertEqual(plan.options["delete"], self.usr_local)
        self.assertIn(f"  then uninstalling MacPorts at {self.local} and Homebrew at {self.usr_local}", outcome.report)
        title = f"To delete with Homebrew at {self.usr_local}, whose `brew` command cannot run"
        self.assertEqual(self.section(outcome, title), [title, "  1 formula: gnu-tar"])

    def test_delete_refuses_an_installation_that_keeps_a_package(self):
        outcome = self.plan(keep=["gsed"], delete=[self.local])
        self.assert_exit(outcome, 1)
        self.assertIn(f"    --delete {self.local}: MacPorts at {self.local} cannot be deleted while it keeps gsed. "
                      "Settle what stays in it, or plan without --delete", outcome.problems)


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
        # What stays keeps its installation: no phase 6, and the overview says which packages hold it.
        self.assertEqual(plan.options["remove_manager"], "")
        self.assertNotIn(6, [phase.number for phase in plan.phases])
        self.assertEqual(outcome.report[2], f"  MacPorts at {self.local} stays installed, because it keeps aria2, "
                                            "dd_rescue, libidn2")
        title = f"Staying in MacPorts at {self.local}"
        self.assertEqual(self.section(outcome, title)[-1], (
            "  To move one of these after all, plan with `--replace NAME=OTHER`; to uninstall one without a "
            "replacement, with `--uninstall NAME`"))

    def test_terminal_answers(self):
        ask = FakeAsk({"aria2": "no", "to replace it?": "yes", "libidn2": "drop"})
        plan = self.plan(ask=ask).plan
        self.assertEqual(sorted(m.source.name for m in plan.mappings), ["dd_rescue", "wget"])
        self.assertNotIn("aria2", [p.name for p in plan.roots])
        self.assertEqual(plan.removal_set[self.local], [("port", "aria2"), ("port", "dd_rescue"), ("port", "libidn2"),
                                                        ("port", "old"), ("port", "wget")])
        self.assertTrue(any("whether you installed it yourself" in q for q in ask.asked))
        self.assertTrue(any("cannot move into Homebrew" in q for q in ask.asked))

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
        self.assertEqual(ask.asked[0].split("\n\n")[0].splitlines(), [
            f"Moving every package into Homebrew 7.0.11 at {self.target.prefix} (Apple Silicon)",
            f"  from MacPorts 2.12.7 at {self.local} (Apple Silicon): 5 ports",
            "  then uninstalling each old installation that the move leaves empty"])
        self.assertFalse(any("Moving every package into" in q for q in ask.asked[1:]))
        medium = next(q for q in ask.asked if "to replace it?" in q)
        self.assertEqual(medium.splitlines(), [
            f"dd_rescue 1.29 (MacPorts at {self.local}): Homebrew at {self.target.prefix} has no exact match. The "
            "closest is formula ddrescue 1.29: another name, for what looks like the same software.",
            "If you answer no, you choose next whether dd_rescue stays or is uninstalled.",
            f"Install ddrescue 1.29 into {self.target.prefix} to replace it?"])
        record = next(q for q in ask.asked if "aria2" in q)
        self.assertEqual(record.split("\n\n")[-1].splitlines(), [
            f"aria2 1.0 (MacPorts at {self.local}): MacPorts has no record of whether you installed it yourself.",
            "If you answer yes, it gets a replacement like every package you installed. If you answer no, it is "
            "treated as a dependency: it is uninstalled with the others and gets no replacement of its own.",
            "Did you install it yourself?"])

    def test_keeping_a_package_says_its_installation_stays(self):
        ask = FakeAsk({"aria2": "no", "to replace it?": "yes"})
        self.plan(ask=ask)
        question = next(q for q in ask.asked if "libidn2" in q)
        self.assertEqual(question.splitlines(), [
            f"libidn2 2.3 (MacPorts at {self.local}) cannot move into Homebrew at {self.target.prefix}: nothing of "
            "that name, or like it, is in Homebrew's package list.",
            f"If you keep it, MacPorts at {self.local} stays installed too.",
            f"Keep it in MacPorts at {self.local}, or drop it (uninstall it without a replacement)?"])
        ask = FakeAsk({"aria2": "no", "to replace it?": "yes"})
        self.plan(ask=ask, keep_managers=True)
        self.assertNotIn("stays installed too", next(q for q in ask.asked if "libidn2" in q))
        ask = FakeAsk({"aria2": "no", "to replace it?": "yes"})
        refused = self.plan(ask=ask, delete=[self.local])
        self.assert_exit(refused, 1)
        self.assertEqual(next(q for q in ask.asked if "libidn2" in q).splitlines()[1], (
            f"If you keep it, MacPorts at {self.local} cannot be deleted, and --delete {self.local} refuses the "
            "plan."))

    def test_a_closest_match_not_taken_says_whether_you_were_asked(self):
        title = f"Staying in MacPorts at {self.local}"
        declined = self.plan(ask=FakeAsk({"aria2": "no", "to replace it?": "no"}))
        self.assertIn("  dd_rescue 1.29: you declined its closest match, formula ddrescue",
                      self.section(declined, title))
        self.assertIn("  dd_rescue 1.29: its closest match, formula ddrescue, needs your yes: plan on a terminal "
                      "without --yes, or with --accept-closest or `--replace dd_rescue=ddrescue`",
                      self.section(self.plan(), title))

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
        stays = self.blocked(issue)
        self.assert_exit(stays, 0)
        self.assertIn(f"  MacPorts at {self.local} stays installed, because a problem stops its uninstall: finding "
                      "ports-damaged-registry. `brew-ports doctor` shows what was found", stays.report)
        self.assertEqual(stays.plan.options["remove_manager"], self.usr_local)
        outcome = self.blocked(issue, delete=[self.local])
        self.assert_exit(outcome, 3)
        self.assertIn(f"brew-ports: this stops the move: finding ports-damaged-registry ({self.local})",
                      outcome.problems)

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
        self.assertIn(f"brew-ports: this stops the move: finding brew-degraded-inventory ({self.usr_local})",
                      outcome.problems)

    def test_casks_keep_passes(self):
        outcome = self.plan(issues=[self.issue])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.removal_set, {self.usr_local: [("formula", "wget")]})


class PackageListTest(PlannerCase):
    """A target without a package list, in which no replacement can be looked up"""

    def test_a_target_without_a_package_list_stops_the_plan(self):
        self.ports_source(port("wget", self.local), port("aria2", self.local, requested=None))
        self.brew_target()
        self.unlist()
        ask = FakeAsk()
        outcome = self.plan(ask=ask)
        self.assert_exit(outcome, 3)
        self.assertEqual(outcome.problems[0], (
            f"brew-ports: this Mac has no package list for Homebrew at {self.target.prefix}, so no replacement can "
            "be looked up. Plan again with --refresh added, which fetches it first"))
        self.assertEqual(outcome.report, [])
        self.assertEqual(ask.asked, [])

    def test_a_macports_without_a_package_list_stops_the_plan(self):
        self.brew_source(formula("wget", self.usr_local))
        self.ports_target()
        self.world.indexes[self.target.prefix] = None
        outcome = self.plan()
        self.assert_exit(outcome, 3)
        self.assertEqual(outcome.problems[0], (
            f"brew-ports: this Mac has no package list for MacPorts at {self.target.prefix}, so no replacement can "
            "be looked up. Plan again with --refresh added, which fetches it first"))


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

    def refresh(self, ask, issues=(), responses=None, before=None):
        """Plan with `--refresh`, the fresh scan and its write stubbed

        @param ask        answers the terminal questions
        @param issues     the findings
        @param responses  the runner's answers to known commands, by argv
        @param before     the scan the plan starts from; None for the host as it is
        @returns          the outcome, the runner and the stub of `scan.build`
        """
        run_dir = self.sd.new_run()
        runner = fake_runner(run_dir, responses=responses)
        bundle = before or self.world.bundle()
        fresh = self.world.bundle()
        with mock.patch("brew_ports.doctor.detect_all", return_value=list(issues)), \
                mock.patch("brew_ports.scan.build", return_value=fresh) as build, \
                mock.patch("brew_ports.scan.write"):
            outcome = planner.build(bundle, options(BREW, self.target.prefix, refresh=True), runner, ask=ask,
                                    state_dir=self.sd, run_dir=run_dir)
        return outcome, runner, build

    def test_blocking_findings_stop_the_refresh(self):
        issue = blocker("system-clt-missing", None, Blocks.ANY)
        ask = FakeAsk(yes=True)
        outcome, runner, build = self.refresh(ask, issues=[issue])
        self.assert_exit(outcome, 3)
        self.assertEqual(ask.confirms, [])
        self.assertEqual(runner.calls, [])
        self.assertIsNone(self.sd.dirty())
        build.assert_not_called()
        self.assertEqual(outcome.problems[:3], [
            "brew-ports: this stops the move: finding system-clt-missing", "    evidence",
            "The package list was not updated (--refresh): the above comes first"])
        self.assertEqual(outcome.report, [])

    def test_refresh_runs_brew_update_and_rescans(self):
        outcome, runner, build = self.refresh(FakeAsk(yes=True), responses={self.update_argv(): FakeResponse()})
        self.assert_exit(outcome, 0)
        self.assertIn(self.update_argv(), runner.calls)
        self.assertEqual(self.sd.dirty()["command"], "plan --refresh")
        build.assert_called_once()
        where = f"Homebrew at {self.target.prefix}"
        self.assertEqual(outcome.report[0], f"Updated the package list of {where} (`{self.target.binary} update`).")
        self.assertFalse([line for line in outcome.report if line.startswith("refresh: ")])
        self.assertTrue(outcome.report[-2].endswith(
            f". Only the package list of {where} was updated; nothing else has changed on this Mac."),
            outcome.report[-2])

    def test_declined_refresh_runs_nothing(self):
        ask = FakeAsk(confirm_answer=False)
        outcome, runner, build = self.refresh(ask)
        self.assert_exit(outcome, 0)
        self.assertEqual(ask.confirms, [
            f"`{self.target.binary} update` updates the package list of Homebrew at {self.target.prefix}. If you "
            "answer no, the plan uses the list as it is.\nRun it before planning?"])
        self.assertEqual(runner.calls, [])
        self.assertIsNone(self.sd.dirty())
        build.assert_not_called()
        self.assertEqual(outcome.report[0], f"The package list of Homebrew at {self.target.prefix} was not updated, as "
                                            "you answered; planned with it as it is.")

    def test_without_a_terminal_the_update_is_not_run(self):
        ask = FakeAsk(tty=False)
        outcome, runner, _ = self.refresh(ask)
        self.assert_exit(outcome, 0)
        self.assertEqual(runner.calls, [])
        self.assertEqual(outcome.report[0], (
            f"The package list of Homebrew at {self.target.prefix} was not updated: --refresh asks first, and there "
            "is no terminal to ask on (add --yes to run it); planned with it as it is."))

    def test_the_update_line_stays_when_the_plan_then_stops(self):
        before = self.world.bundle()
        self.unlist()
        outcome, runner, _ = self.refresh(FakeAsk(yes=True), responses={self.update_argv(): FakeResponse()},
                                          before=before)
        self.assert_exit(outcome, 3)
        self.assertIn(self.update_argv(), runner.calls)
        where = f"Homebrew at {self.target.prefix}"
        self.assertEqual(outcome.report, [f"Updated the package list of {where} (`{self.target.binary} update`)."])
        self.assertEqual(outcome.problems[0], (
            f"brew-ports: this Mac has no package list for {where}, so no replacement can be looked up, although the "
            "update ran. `brew-ports doctor` shows what is wrong with it"))

    def test_a_failed_refresh_exits_4(self):
        outcome, _, _ = self.refresh(FakeAsk(yes=True))
        self.assert_exit(outcome, 4)
        self.assertEqual(outcome.result_file, "plan-refused.json")
        self.assertEqual(outcome.problems[0], f"brew-ports: `{self.target.binary} update` failed (exit 1). Nothing "
                                              "was planned. Fix that, or plan without --refresh")
        self.assertEqual(outcome.report, [])

    def test_a_missing_package_list_does_not_stop_the_refresh(self):
        listed = self.world.catalogues[self.target.prefix]
        self.unlist()
        before = self.world.bundle()
        self.world.catalogues[self.target.prefix] = listed
        outcome, runner, build = self.refresh(FakeAsk(yes=True), responses={self.update_argv(): FakeResponse()},
                                              before=before)
        self.assert_exit(outcome, 0)
        self.assertIn(self.update_argv(), runner.calls)
        build.assert_called_once()

    def test_a_declined_refresh_still_needs_a_package_list(self):
        self.unlist()
        ask = FakeAsk(confirm_answer=False)
        outcome, runner, _ = self.refresh(ask)
        self.assert_exit(outcome, 3)
        self.assertEqual(runner.calls, [])
        self.assertEqual(ask.confirms, [
            f"`{self.target.binary} update` updates the package list of Homebrew at {self.target.prefix}. If you "
            "answer no, no plan is made, as this Mac has no package list of it yet.\nRun it before planning?"])
        missing = (f"brew-ports: this Mac has no package list for Homebrew at {self.target.prefix}, so no replacement "
                   "can be looked up. ")
        self.assertEqual(outcome.problems[0], missing + "Plan again and answer yes to the update that --refresh "
                                                        "offers, which fetches it")
        # Nothing was planned, so standard output says nothing of a plan.
        self.assertEqual(outcome.report, [])
        unasked, _, _ = self.refresh(FakeAsk(tty=False))
        self.assert_exit(unasked, 3)
        self.assertEqual(unasked.problems[0], missing + "--refresh asks before it fetches one, and there is no "
                                                        "terminal to ask on: plan again with --yes added")

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
        self.assertEqual([p.number for p in back.phases], [0, 1, 2, 3, 4, 5, 6, 7, 8])
        copy = self.path("copy.json")
        with open(copy, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), text)
        self.assertEqual(os.path.basename(outcome.path), "plan.json")
        self.assertEqual(outcome.report[-3:], [
            f"Plan saved as {copy}. Nothing has changed on this Mac.",
            f"Run folder: {report.tilde(os.path.dirname(outcome.path))}",
            f"Next: brew-ports apply {copy} --dry-run   (lists every command, changes nothing)"])

    def test_refused_plan_is_written_and_never_copied(self):
        outcome = self.plan(only=["gsed"], out=self.path("copy.json"))
        self.assert_exit(outcome, 1)
        self.assertIsNone(outcome.plan)
        self.assertIsNotNone(outcome.draft)
        self.assertEqual(os.path.basename(outcome.path), "plan-refused.json")
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(outcome.path), "plan.json")))
        self.assertFalse(os.path.exists(self.path("copy.json")))
        with open(outcome.path, encoding="utf-8") as fh:
            data = json.load(fh)
        reason = (f"gsed cannot be uninstalled from MacPorts at {self.local}: wget needs it, and is not in --only. "
                  "Add wget to --only, or take gsed out")
        self.assertEqual(data["refused"]["exit"], 1)
        self.assertEqual(data["refused"]["reasons"], [reason])
        self.assertEqual(data["plan"]["removal_set"], {self.local: [["port", "gsed"]]})
        with self.assertRaises(TypeError):
            model.from_dict(model.Plan, data)
        self.assertEqual(outcome.problems, [
            "brew-ports: no plan was made: 1 thing to settle first", f"    {reason}",
            f"No plan was saved. The reasons are also in {report.tilde(outcome.path)}."])
        self.assertFalse([line for line in outcome.report if line.startswith(("What `brew-ports apply`", "Next:"))])

    def test_a_refused_plan_leaves_the_out_file_untouched(self):
        copy = self.write("copy.json", "an earlier plan\n")
        self.assert_exit(self.plan(only=["gsed"], out=copy), 1)
        with open(copy, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "an earlier plan\n")


class CommandTest(PlannerCase):
    """`brew-ports plan` from the command line to the printed report"""

    def setUp(self):
        super().setUp()
        self.ports_source(port("wget", self.local))
        self.brew_target()

    def command(self, *argv):
        """Run `brew-ports plan` into the host's Homebrew target, without a terminal

        @param argv  the arguments after the target's
        @returns     the exit code, what went to standard output and what went to the error stream
        """
        args = cli.build_parser().parse_args(["plan", "--target", "brew", "--target-prefix", self.target.prefix,
                                              *argv])
        console = report.Console(stream=io.StringIO(), err=io.StringIO())
        ctx = Context(args, console, self.sd, tty=False, environ={"HOME": "/Users/alice"})
        with mock.patch("brew_ports.scan.obtain", return_value=(self.world.bundle(), False)), \
                mock.patch("brew_ports.doctor.detect_all", return_value=[]):
            code = planner.cmd_plan(ctx, make_runner=lambda c, r: fake_runner(r))
        return code, console.stream.getvalue(), console.err.getvalue()

    def test_cmd_plan_prints_the_report(self):
        code, out, err = self.command()
        self.assertEqual((code, err), (0, ""))
        run, = os.listdir(self.sd.runs)
        folder = os.path.join(self.sd.runs, run)
        saved = os.path.join(folder, "plan.json")
        self.assertIn("\n  1 under the same name: wget\n", out)
        self.assertTrue(out.endswith(
            f"\nPlan saved in the run folder, {report.tilde(folder)}. Nothing has changed on this Mac.\n"
            f"Next: brew-ports apply {saved} --dry-run   (lists every command, changes nothing)\n"), out)

    def test_cmd_plan_prints_the_problems_on_the_error_stream(self):
        code, out, err = self.command("--leave", "nosuch")
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(err, f"brew-ports: --leave nosuch: no package named nosuch is installed in MacPorts at "
                              f"{self.local}\n")


# The report ----------------------------------------------------------------------------------------------

class ReportTest(PlannerCase):
    """The report of a plan that was made: its sections and its closing lines"""

    def setUp(self):
        super().setUp()
        self.ports_source(port("wget", self.local, "1.25.0", deps=["libidn2"]),
                          port("libidn2", self.local, "2.3", requested=False), port("gsed", self.local, "4.9"),
                          port("dd_rescue", self.local, "1.29"))
        self.brew_target()

    def test_the_replacements_the_uninstalls_and_the_closing_lines(self):
        # The commands hold the temporary folder, whose length differs from machine to machine: none is cut here.
        with mock.patch.object(plan_report, "COMMAND_WIDTH", 10_000):
            outcome = self.plan(accept_medium=True)
        self.assert_exit(outcome, 0)
        title = f"Replacements in Homebrew at {self.target.prefix}: 3 packages"
        self.assertEqual(self.section(outcome, title), [
            title,
            "  1 under the same name: wget",
            "  1 under another name: gsed is gnu-sed",
            "  1 by the closest match, accepted by --accept-closest",
            "      dd_rescue 1.29 becomes ddrescue 1.29: another name, for what looks like the same software",
            "  To install: ddrescue, gnu-sed, wget"])
        title = f"To uninstall from MacPorts at {self.local}"
        self.assertEqual(self.section(outcome, title), [
            title, "  4 ports, 1 of them a dependency", "      dd_rescue, gsed, libidn2, wget"])
        title = "What `brew-ports apply` will do, asking before each step that changes something"
        self.assertEqual(self.section(outcome, title), [
            title, "  0  Checks before starting", "  1  Save a record for undo", "  3  Install the replacements",
            f"       {self.target.binary} install --formula wget",
            f"       {self.target.binary} install --formula ddrescue gnu-sed",
            "  4  Check the replacements", "  5  Uninstall the old packages",
            f"  6  Uninstall MacPorts at {self.local}: save {self.local}/etc in the run folder, then delete "
            f"{self.local}, /Applications/MacPorts", "  7  Clean up the shell files", "  8  Final check"])
        self.assertEqual(outcome.report[-3:], [
            "", f"Plan saved in the run folder, {report.tilde(os.path.dirname(outcome.path))}. Nothing has changed "
                "on this Mac.",
            f"Next: brew-ports apply {outcome.path} --dry-run   (lists every command, changes nothing)"])
        answered = self.plan(ask=FakeAsk({"to replace it?": "yes"}))
        self.assertIn("  1 by the closest match, which you accepted", answered.report)

    def test_a_folder_that_does_not_look_like_its_manager_stays(self):
        self.unmark(self.local)
        outcome = self.plan(accept_medium=True)
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.options["remove_manager"], "")
        self.assertEqual(outcome.report[2], (
            f"  MacPorts at {self.local} stays installed: {self.local} has no etc/macports/macports.conf, so it does "
            "not look like MacPorts, and brew-ports deletes no such folder"))
        self.assertFalse([line for line in outcome.report if line.startswith("  6  ")])

    def test_verbose_adds_every_replacement_and_how_it_was_found(self):
        title = "Every replacement, and how it was found"
        self.assertNotIn(title, self.plan(accept_medium=True).report)
        table = self.section(self.plan(accept_medium=True, verbose=True), title)
        self.assertEqual(table[1].split(), ["package", "from", "replacement", "match", "how", "it", "was", "found"])
        self.assertEqual([row.split()[:6] for row in table[3:]], [
            ["dd_rescue", self.local, "formula", "ddrescue", "closest", "match"],
            ["gsed", self.local, "formula", "gnu-sed", "same", "package"],
            ["wget", self.local, "formula", "wget", "same", "package"]])


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

    def draft(self, **fields: Any) -> planner.Draft:
        """Return the draft of a move out of both old installations, which hold two ports, a formula and a cask

        @param fields  `Draft` fields besides the target, the sources and their units
        @returns       the draft
        """
        packages = [make_package("wget", "port", "/opt/local"), make_package("zlib", "port", "/opt/local"),
                    make_package("jq", "formula", "/usr/local"), make_package("vlc", "cask", "/usr/local")]
        units = [unit for inst in (self.ports, self.intel) for unit in plan_sets.units_of(inst, packages)]
        return planner.Draft(target=self.target, sources=[self.ports, self.intel],
                             units={unit.key: unit for unit in units}, **fields)

    def test_the_overview_names_every_installation_and_the_removals(self):
        into = "Homebrew 5.0.2 at /opt/homebrew (Apple Silicon)"
        sources = ["  from MacPorts 2.10.5 at /opt/local (Apple Silicon): 2 ports",
                   "  from Homebrew 4.6.0 at /usr/local (Intel): 1 formula, 1 cask"]
        head = [f"Moving every package into {into}"] + sources
        both = [self.ports, self.intel]
        self.assertEqual(plan_report.overview(self.draft(candidates=both)), head + [
            "  then uninstalling each old installation that the move leaves empty"])
        moved = self.draft(removed=both, settled=True)
        wget = next(unit for unit in moved.units.values() if unit.name == "wget")
        moved.roots[wget.key] = plan_sets.Root(wget, "installed on request", status=plan_sets.MIGRATED)
        self.assertEqual(plan_report.overview(moved), head + [
            "  then uninstalling MacPorts at /opt/local and Homebrew at /usr/local, which will both be empty"])
        stays = {"/usr/local": "stays installed, because it keeps vlc"}
        # Without a package that gets a replacement, the plan does not say that it moves any.
        self.assertEqual(plan_report.overview(self.draft(removed=[self.ports], stays=stays, settled=True)), [
            f"No package moves into {into}"] + sources + [
            "  then uninstalling MacPorts at /opt/local, which will be empty",
            "  Homebrew at /usr/local stays installed, because it keeps vlc"])
        self.assertEqual(plan_report.overview(self.draft(unreadable={"/usr/local"}))[2],
                         "  from Homebrew 4.6.0 at /usr/local (Intel): its packages are unknown")

    def test_a_major_version_jump_is_said_in_plain_words(self):
        unit = self.unit("giflib", "4.2.3_0")
        self.assertEqual(plan_report.medium_question(unit, self.mapping(unit, "giflib", "5.2.2"), self.target),
                         "giflib 4.2.3 (MacPorts at /opt/local): Homebrew at /opt/homebrew has no exact match. The "
                         "closest is formula giflib 5.2.2: a newer major version, so programs built against 4.x may "
                         "not work with it.\n"
                         "If you answer no, you choose next whether giflib stays or is uninstalled.\n"
                         "Install giflib 5.2.2 into /opt/homebrew to replace it?")

    def test_another_name_or_else_the_evidence_says_how_it_differs(self):
        unit = self.unit("dd_rescue", "1.29")
        self.assertIn("formula ddrescue 1.30: another name, for what looks like the same software.",
                      plan_report.medium_question(unit, self.mapping(unit, "ddrescue", "1.30"), self.target))
        unit = self.unit("foo", "1.2")
        line = "version: foo and foo2 share the source's major; foo is the newest"
        self.assertIn(f"formula foo 1.3: {line}.",
                      plan_report.medium_question(unit, self.mapping(unit, "foo", "1.3", (line,)), self.target))

    def test_a_long_command_is_cut_at_a_word(self):
        names = [f"formula{n:02d}" for n in range(20)]
        action = model.Action(action_id="3.install.bottled", kind="command", argv=["/x/brew", "install"] + names,
                              sudo=False, description="install the replacements")
        whole = "/x/brew install " + " ".join(names)
        self.assertEqual(plan_report._command(action, True), whole)
        cut = plan_report._command(action, False)
        shown = cut.split(" ... ")[0]
        self.assertTrue(whole.startswith(shown + " ") and len(shown) <= plan_report.COMMAND_WIDTH, cut)
        left = len(whole.split()) - len(shown.split())
        self.assertEqual(cut, f"{shown} ... ({left} more words; --verbose shows all)")
        self.assertEqual(shown.split()[-1], "formula08")

    def test_the_language_lists_say_what_pipx_moves(self):
        files = {"pip": "/run/language-pip.txt"}
        self.assertEqual(plan_report._language(self.draft(language_files=files)), [
            "", "Python packages are not moved. The list to reinstall them from", "  /run/language-pip.txt"])
        self.assertEqual(plan_report._language(self.draft(language_files=files, pipx=True))[1],
                         "Of the Python packages, only the Python tools that pipx installs move. The list of them all")
        files.update(gem="/run/language-gem.txt", cpan="/run/language-cpan.txt")
        self.assertEqual(plan_report._language(self.draft(language_files=files))[1],
                         "Perl, Ruby and Python packages are not moved. Lists to reinstall them from")

    def test_keeping_a_package_names_the_installation_it_keeps(self):
        unit = self.unit("zlib", "1.3")
        note = "nothing of that name, or like it, is in Homebrew's package list"
        first = f"zlib 1.3 (MacPorts at /opt/local) cannot move into Homebrew at /opt/homebrew: {note}."
        last = "Keep it in MacPorts at /opt/local, or drop it (uninstall it without a replacement)?"
        ask = plan_report.unmigratable_question
        self.assertEqual(ask(unit, note, self.target, emptied=True).splitlines(), [
            first, "If you keep it, MacPorts at /opt/local stays installed too.", last])
        self.assertEqual(ask(unit, note, self.target, emptied=False).splitlines(), [first, last])
        self.assertEqual(ask(unit, note, self.target, emptied=True, forced=True).splitlines()[1],
                         "If you keep it, MacPorts at /opt/local cannot be deleted, and --delete /opt/local refuses "
                         "the plan.")
        self.assertEqual(ask(unit, note, self.target, emptied=False, manual=True).splitlines()[-1],
                         "Keep it in MacPorts at /opt/local, or drop it (the plan then gives you the command to "
                         "uninstall it, since Homebrew asks for your password)?")


if __name__ == "__main__":
    unittest.main()

"""What the plan fixes ahead of the run: upgrades, repairs, installs, rebuilds and the phase 6 previews"""

import os
import unittest
from unittest import mock

from brew_ports import doctor, plan_phases, runner
from brew_ports.homebrew import actions as brew_actions
from brew_ports.model import Confidence, Manager, Mapping, OnFailure, Severity
from tests.unit.fixtures.doctor.builders import service
from tests.unit.fixtures.planner.builders import (FakeAsk, PlannerCase, actions, cask, catalogue, formula, instance,
                                                  port)

PAYLOAD = {"formulae": {
    "wget": {"stable_version": "1.25.0", "bottle_checksum": "abc", "homepage": "https://www.gnu.org/software/wget/",
             "stable_dependencies": ["openssl@3", {"pkgconf": ":build"}]},
    "openssl@3": {"stable_version": "3.6.0", "bottle_checksum": "abc"},
    "curl": {"stable_version": "8.17.0", "bottle_checksum": "abc", "stable_dependencies": ["openssl@3"]},
    "ddrescue": {"stable_version": "1.29"},
    "gnu-sed": {"stable_version": "4.10", "aliases": ["gsed"], "bottle_checksum": "abc"},
    "pkgconf": {"stable_version": "2.5.1"},
}}


def ids(plan, number):
    """Return the action ids of one phase of a plan

    @param plan    the plan
    @param number  the phase number
    @returns       the ids, in phase order
    """
    return [a.action_id for a in actions(plan, number)]


class BrewUpgradesTest(PlannerCase):
    """The upgrades a Homebrew target needs for the mapped targets, and a pinned blocker"""

    def setUp(self):
        super().setUp()
        self.ports_source(port("wget", self.local, "1.25.0"))

    def make_target(self, **openssl):
        """Add the Homebrew target with an outdated openssl@3, curl on it, and an outdated pkgconf

        @param openssl  `Package` fields of openssl@3 over its outdated, unrequested 3.5.0
        """
        fields = {"version": "3.5.0", "outdated": True, "requested": False}
        fields.update(openssl)
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("openssl@3", prefix, **fields),
                         formula("curl", prefix, version="8.16.0", deps=["openssl@3"]),
                         formula("pkgconf", prefix, version="2.4.0", outdated=True),
                         payload=PAYLOAD, outdated_formulae={"openssl@3": "3.6.0", "pkgconf": "2.5.1"})

    def test_outdated_dependency_and_its_dependents(self):
        self.make_target()
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual(plan.target_upgrades, ["openssl@3", "curl"])
        text = self.text(outcome)
        self.assertRegex(text, r"\n  openssl@3 +3\.5\.0 -> 3\.6\.0 +a dependency of wget\n"
                               r"  Checked after the upgrades, and installed again if one lost a library: curl\n")
        self.assertNotIn("8.16.0 ->", text)                     # curl has no newer version to go to
        # Only mapped targets and companions are upgraded by name; build-only dependencies are no upgrades.
        self.assertNotIn("3.upgrade.formulae", ids(plan, 3))
        self.assertNotIn("pkgconf", plan.target_upgrades)

    def test_what_uses_an_upgraded_formula_is_only_checked(self):
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("openssl@3", prefix, version="3.5.0", outdated=True, requested=False),
                         formula("curl", prefix, version="8.16.0", deps=["openssl@3"], outdated=True),
                         payload=PAYLOAD, outdated_formulae={"openssl@3": "3.6.0", "curl": "8.17.0"})
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        # curl has a newer version too. Homebrew would upgrade it after openssl@3, with what curl needs; the
        # commands of phase 3 keep Homebrew to what they name, so the plan lists all that is upgraded.
        text = self.text(outcome)
        self.assertIn("\n  Checked after the upgrades, and installed again if one lost a library: curl\n", text)
        self.assertNotIn("8.16.0 ->", text)
        for action in actions(outcome.plan, 3):
            env = runner.profile_env(action.env_profile, {}, prefix=prefix)
            self.assertEqual(env["HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK"], "1", action.action_id)
        # With --upgrade-all the plan upgrades curl by name.
        every = self.plan(upgrade_all=True)
        self.assertEqual(next(a.argv[-2:] for a in actions(every.plan, 3) if a.action_id == "3.upgrade.others"),
                         ["curl", "openssl@3"])
        self.assertRegex(self.text(every), r"\n  curl +8\.16\.0 -> 8\.17\.0\n")

    def duplicate(self, **openssl):
        """Add a Homebrew target that holds wget too, at the version of the catalogue, on an outdated openssl@3

        @param openssl  `Package` fields of openssl@3 over its outdated, unrequested 3.5.0
        """
        fields = {"version": "3.5.0", "outdated": True, "requested": False}
        fields.update(openssl)
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("wget", prefix, version="1.25.0", deps=["openssl@3"]),
                         formula("openssl@3", prefix, **fields),
                         payload=PAYLOAD, outdated_formulae={"openssl@3": "3.6.0"})

    def test_a_replacement_that_is_installed_upgrades_nothing(self):
        self.duplicate()
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.target_upgrades, [])
        self.assertEqual(ids(outcome.plan, 3), [])              # phase 3 has nothing to run for wget
        self.assertNotIn("Upgrades in", self.text(outcome))

    def test_a_pin_under_an_installed_replacement_is_in_nobodys_way(self):
        self.duplicate(pinned=True)
        self.assert_exit(self.plan(), 0)

    def test_what_a_replacement_uses_is_never_optional(self):
        self.duplicate()
        outcome = self.plan(upgrade_all=True)
        self.assert_exit(outcome, 0)
        # The option upgrades openssl@3, and the move needs it all the same: the installed wget uses it, so a
        # break of it has to stop the run before the old wget is uninstalled.
        self.assertEqual(outcome.plan.target_upgrades, ["openssl@3"])
        self.assertEqual(outcome.plan.optional_upgrades, [])
        self.assertRegex(self.text(outcome), r"\nOther upgrades in .*, as --upgrade-all asks\n(.*\n){2}  openssl@3 ")

    def test_a_pinned_install_blocker_exits_1(self):
        self.make_target(pinned=True)
        outcome = self.plan()
        self.assert_exit(outcome, 1)
        brew = self.target.binary
        self.assertEqual(outcome.problems[:2], [
            "brew-ports: no plan was made: 1 thing to settle first",
            "    installing the replacement of wget would upgrade openssl@3 (a dependency of wget), which is pinned. "
            f"Plan on a terminal without --yes to be asked about the pin, or run `{brew} unpin openssl@3` and plan "
            "again with --rescan, or plan with `--leave wget`"])
        self.assertEqual(outcome.draft.target_upgrades, ["openssl@3", "curl"])
        self.assertEqual(self.section(outcome, f"Pinned in Homebrew at {self.target.prefix}")[1:], [
            f"  openssl@3 3.5.0, newest 3.6.0: stays pinned. To upgrade it: `{brew} unpin openssl@3`, then "
            f"`{brew} upgrade --formula openssl@3`",
            "  On a terminal and without --yes, `brew-ports plan` asks whether to remove each pin."])

    def test_keeping_the_root_clears_the_blocker(self):
        self.make_target(pinned=True)
        self.assert_exit(self.plan(keep=["wget"]), 0)

    def test_the_pin_in_the_way_is_put_to_the_user(self):
        self.make_target(pinned=True)
        ask = FakeAsk({"Remove the pin": "no"})
        outcome = self.plan(ask=ask)
        self.assert_exit(outcome, 1)
        at_target = f"Homebrew at {self.target.prefix}"
        self.assertTrue(ask.asked[0].endswith(
            f"\nopenssl@3 in {at_target} is pinned at 3.5.0; the newest version is 3.6.0. Installing the replacement "
            "of wget would upgrade openssl@3 (a dependency of wget).\n"
            "If you answer yes, the move removes the pin and upgrades it to 3.6.0. If you answer no, it stays pinned "
            "and no plan is made.\n"
            "Remove the pin and upgrade openssl@3?"), ask.asked[0])
        self.assertEqual(outcome.problems[1],
                         "    installing the replacement of wget would upgrade openssl@3 (a dependency of wget), which "
                         "stays pinned, as you answered. Plan again and answer yes for it, or plan with `--leave wget`")
        self.assertIn("  openssl@3 3.5.0, newest 3.6.0: stays pinned, as you answered. To upgrade it: ",
                      self.text(outcome))
        # --yes answers no question about a pin: what the user pinned stays until they say otherwise.
        self.assert_exit(self.plan(ask=FakeAsk({"Remove the pin": "yes"}, yes=True)), 1)

    def test_a_yes_removes_the_pin_and_upgrades_the_formula(self):
        self.make_target(pinned=True)
        outcome = self.plan(ask=FakeAsk({"Remove the pin": "yes"}))
        self.assert_exit(outcome, 0)
        acts = {a.action_id: a for a in actions(outcome.plan, 3)}
        brew = self.target.binary
        self.assertEqual(list(acts)[:2], ["3.unpin.formulae", "3.upgrade.formulae"])
        self.assertEqual(acts["3.unpin.formulae"].argv[2:], [brew, "unpin", "openssl@3"])
        self.assertEqual(acts["3.upgrade.formulae"].argv[2:], [brew, "upgrade", "--formula", "openssl@3"])
        self.assertEqual(self.section(outcome, f"Pinned in Homebrew at {self.target.prefix}")[1:], [
            "  openssl@3 3.5.0 -> 3.6.0: the pin is removed and it is upgraded, as you answered",
            "  `brew-ports rollback` does not put a removed pin back."])

    def test_a_pinned_formula_that_uses_an_upgraded_one_is_asked(self):
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("openssl@3", prefix, version="3.5.0", outdated=True, requested=False),
                         formula("curl", prefix, version="8.16.0", deps=["openssl@3"], pinned=True),
                         payload=PAYLOAD, outdated_formulae={"openssl@3": "3.6.0"})
        ask = FakeAsk({"Remove the pin": "no"})
        outcome = self.plan(ask=ask)
        self.assert_exit(outcome, 1)
        why = ("installing the replacement of wget upgrades openssl@3, so curl, which uses it, may have to be "
               "installed again")
        self.assertTrue(ask.asked[0].endswith(
            f"\ncurl in Homebrew at {prefix} is pinned at 8.16.0. I{why[1:]}.\n"
            "If you answer yes, the move removes the pin. If you answer no, it stays pinned and no plan is made.\n"
            "Remove the pin of curl?"), ask.asked[0])
        self.assertEqual(outcome.problems[1], f"    {why}, and it stays pinned, as you answered. Plan again and "
                                              "answer yes for it, or plan with `--leave wget`")
        self.assertIn(f"  curl 8.16.0: stays pinned, as you answered. To remove the pin: `{self.target.binary} unpin "
                      "curl`\n", self.text(outcome))
        # A yes removes the pin; curl has no newer version, so nothing upgrades it.
        outcome = self.plan(ask=FakeAsk({"Remove the pin": "yes"}))
        self.assert_exit(outcome, 0)
        self.assertEqual([i for i in ids(outcome.plan, 3) if "pin" in i or "upgrade" in i], ["3.unpin.formulae"])
        self.assertIn("  curl 8.16.0: the pin is removed, as you answered\n", self.text(outcome))

    def two_pins(self):
        """Add a target whose pinned openssl@3 a replacement needs, with a pinned curl that uses openssl@3

        @returns  the question about each, as it ends
        """
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("openssl@3", prefix, version="3.5.0", outdated=True, requested=False, pinned=True),
                         formula("curl", prefix, version="8.16.0", deps=["openssl@3"], pinned=True),
                         payload=PAYLOAD, outdated_formulae={"openssl@3": "3.6.0"})
        return "Remove the pin and upgrade openssl@3?", "Remove the pin of curl?"

    def test_the_questions_end_with_the_first_no(self):
        first, second = self.two_pins()
        ask = FakeAsk({first: "no", second: "yes"})
        outcome = self.plan(ask=ask)
        self.assert_exit(outcome, 1)
        # What is upgraded is asked about before what uses it, and no plan is made after the no.
        self.assertEqual([q.rsplit("\n", 1)[-1] for q in ask.asked], [first])
        self.assertEqual(outcome.problems[0], "brew-ports: no plan was made: 2 things to settle first")
        self.assertTrue(outcome.problems[1].endswith("which stays pinned, as you answered. Plan again and answer yes "
                                                     "for it, or plan with `--leave wget`"), outcome.problems[1])
        self.assertTrue(outcome.problems[2].endswith("and it is pinned. `brew-ports plan` asks about this pin once "
                                                     "the other points are settled, or plan with `--leave wget`"),
                        outcome.problems[2])
        brew = self.target.binary
        self.assertEqual(self.section(outcome, f"Pinned in Homebrew at {self.target.prefix}")[1:], [
            f"  openssl@3 3.5.0, newest 3.6.0: stays pinned, as you answered. To upgrade it: `{brew} unpin openssl@3`, "
            f"then `{brew} upgrade --formula openssl@3`",
            f"  curl 8.16.0: stays pinned. To remove the pin: `{brew} unpin curl`"])

    def test_a_yes_for_a_plan_that_is_not_made_removes_no_pin(self):
        first, second = self.two_pins()
        ask = FakeAsk({first: "yes", second: "no"})
        outcome = self.plan(ask=ask)
        self.assert_exit(outcome, 1)
        self.assertEqual([q.rsplit("\n", 1)[-1] for q in ask.asked], [first, second])
        self.assertEqual(self.section(outcome, f"Pinned in Homebrew at {self.target.prefix}")[1:], [
            "  openssl@3 3.5.0: you answered yes; it stays pinned, as no plan is made",
            f"  curl 8.16.0: stays pinned, as you answered. To remove the pin: `{self.target.binary} unpin curl`"])
        # A plan that is not made upgrades nothing, so it has no word of what an upgrade leaves behind.
        self.assertNotIn("The old version of each upgraded formula", self.text(outcome))

    def test_a_plan_refused_for_another_reason_asks_about_no_pin(self):
        self.make_target(pinned=True)
        # wget alone cannot leave MacPorts while a port that stays there needs it.
        self.world.packages.append(port("fetcher", self.local, "1.0", deps=["wget"]))
        ask = FakeAsk({"Remove the pin": "yes"})
        outcome = self.plan(ask=ask, only=["wget"], upgrade_all=True)
        self.assert_exit(outcome, 1)
        self.assertIn("fetcher needs it", self.text(outcome))
        self.assertEqual([q for q in ask.asked if "Remove the pin" in q], [])
        self.assertIn("is pinned. `brew-ports plan` asks about this pin once the other points are settled",
                      self.text(outcome))


class PortsUpgradesTest(PlannerCase):
    """The upgrades a MacPorts target needs, an epoch change among them"""

    def test_epoch_bump_and_the_upgrade_dependents(self):
        self.brew_source(formula("wget", self.usr_local, version="1.25.0"))
        self.ports_target(port("zlib", self.local, "1.3", epoch=0, outdated=True, requested=False),
                          port("curl", self.local, "8.16.0", deps=["zlib"]),
                          drop=["wget"], add=[{"name": "wget", "version": "1.25.0", "depends_lib": "port:zlib"},
                                              {"name": "zlib", "version": "1.3", "revision": 1, "epoch": 1},
                                              {"name": "curl", "version": "8.17.0"}])
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.target_upgrades, ["zlib", "curl"])
        self.assertIn("1.3_0 (epoch 0) -> 1.3_1 (epoch 1)", self.text(outcome))

    def host(self, *more, add=()):
        """Make a move of wget into a MacPorts whose zlib, which wget needs, is outdated

        @param more  further ports of the target
        @param add   further PortIndex entries
        @returns     the target's `port`, as a command of the plan report names it
        """
        self.brew_source(formula("wget", self.usr_local, version="1.25.0"))
        self.ports_target(port("zlib", self.local, "1.3", outdated=True, requested=False), *more, drop=["wget"],
                          add=[{"name": "wget", "version": "1.25.0", "depends_lib": "port:zlib"},
                               {"name": "zlib", "version": "1.3", "revision": 1}, *add])
        return f"sudo {self.target.binary}"

    def test_a_port_that_uses_an_upgraded_port_is_only_checked(self):
        self.host(port("curl", self.local, "8.16.0", deps=["zlib"], outdated=True),
                  add=[{"name": "curl", "version": "8.17.0"}])
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        # `port install wget` upgrades what wget needs. Nothing upgrades curl, which only uses zlib.
        self.assertEqual(ids(outcome.plan, 3), ["3.install.wget"])
        text = self.text(outcome)
        self.assertRegex(text, r"\n  zlib +1\.3_0 -> 1\.3_1 +a dependency of wget\n"
                               r"  Checked after the upgrades, and installed again if one lost a library: curl\n")
        self.assertNotIn("8.16.0_0 ->", text)

    def test_upgrade_all_upgrades_a_port_that_uses_an_upgraded_one(self):
        self.host(port("curl", self.local, "8.16.0", deps=["zlib"], outdated=True),
                  add=[{"name": "curl", "version": "8.17.0"}])
        outcome = self.plan(upgrade_all=True)
        self.assert_exit(outcome, 0)
        self.assertEqual(ids(outcome.plan, 3), ["3.upgrade.curl", "3.upgrade.zlib", "3.install.wget"])
        self.assertEqual(outcome.plan.optional_upgrades, ["curl"])
        others = self.section(outcome, f"Other upgrades in MacPorts at {self.local}, as --upgrade-all asks")
        self.assertRegex(others[3], r"^  curl +8\.16\.0_0 -> 8\.17\.0_0$")
        self.assertEqual(others[4:], ["  The old version of each upgraded port stays stored, switched off; afterwards "
                                      "`brew-ports doctor` offers to uninstall those versions."])
        self.assertNotIn("Checked after the upgrades", self.text(outcome))

    def test_a_replaced_port_stays_with_the_command_that_replaces_it(self):
        sudo_port = self.host(port("py39-foo", self.local, "1.0", outdated=True, renamed_to="py313-foo"))
        outcome = self.plan(upgrade_all=True)
        self.assert_exit(outcome, 0)
        # `port upgrade` would put py313-foo in its place, which the checks of the move would take for a loss.
        self.assertEqual(ids(outcome.plan, 3), ["3.upgrade.zlib", "3.install.wget"])
        self.assertEqual(self.section(outcome, f"Not upgraded by --upgrade-all in MacPorts at {self.local}")[1:], [
            f"  py39-foo: MacPorts replaced it with py313-foo. To make that change: `{sudo_port} upgrade py39-foo`"])
        # While a Homebrew stays installed, MacPorts builds in trace mode.
        kept = self.plan(upgrade_all=True, keep_managers=True)
        self.assertIn(f"To make that change: `{sudo_port} -t upgrade py39-foo`\n", self.text(kept))


class UpgradeAllTest(PlannerCase):
    """`--upgrade-all`: every other outdated package of the target, and what it leaves as it is"""

    def brew_host(self):
        """Make a move of wget into a Homebrew with outdated formulae and apps, some of which have to stay

        openssl@3 is a dependency of the replacement, pkgconf is needed by nothing, gnu-sed is pinned and uses
        ddrescue, firefox is an app, and docker-desktop is an app whose installer asks for the password.
        """
        self.ports_source(port("wget", self.local, "1.25.0"))
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("openssl@3", prefix, version="3.5.0", outdated=True, requested=False),
                         formula("pkgconf", prefix, version="2.4.0", outdated=True),
                         formula("ddrescue", prefix, version="1.28", outdated=True),
                         formula("gnu-sed", prefix, version="4.9", outdated=True, pinned=True, deps=["ddrescue"]),
                         cask("firefox", prefix, version="140.0", outdated=True),
                         cask("docker-desktop", prefix, outdated=True, privileged_install=True),
                         payload=PAYLOAD, outdated_casks={"firefox": "141.0"},
                         outdated_formulae={"openssl@3": "3.6.0", "pkgconf": "2.5.1", "ddrescue": "1.29",
                                            "gnu-sed": "4.10"})

    def test_without_the_option_only_what_the_replacements_need(self):
        self.brew_host()
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.target_upgrades, ["openssl@3"])
        self.assertEqual([i for i in ids(outcome.plan, 3) if i.startswith("3.upgrade")], [])
        self.assertEqual(outcome.plan.options["upgrade_all"], "false")
        self.assertNotIn("--upgrade-all", self.text(outcome))

    def test_the_option_upgrades_every_other_formula_and_app(self):
        self.brew_host()
        outcome = self.plan(upgrade_all=True)
        self.assert_exit(outcome, 0)
        plan, brew = outcome.plan, self.target.binary
        acts = {a.action_id: a for a in actions(plan, 3)}
        # The upgrades that the option adds are a command of their own, the apps follow, then the installs.
        self.assertEqual(list(acts), ["3.upgrade.others", "3.upgrade.casks", "3.install.bottled"])
        self.assertEqual(acts["3.upgrade.others"].argv[2:], [brew, "upgrade", "--formula", "openssl@3", "pkgconf"])
        self.assertEqual(acts["3.upgrade.casks"].argv[2:], [brew, "upgrade", "--cask", "firefox"])
        self.assertEqual(plan.target_upgrades, ["openssl@3", "pkgconf"])
        self.assertEqual((plan.optional_upgrades, plan.optional_casks), (["pkgconf"], ["firefox"]))
        self.assertEqual(plan.options["upgrade_all"], "true")
        at_target = f"Homebrew at {self.target.prefix}"
        text = self.text(outcome)
        self.assertIn(f"\nOther upgrades in {at_target}, as --upgrade-all asks\n", text)
        self.assertRegex(text, r"\n  pkgconf +2\.4\.0 -> 2\.5\.1\n  firefox \(app\) +140\.0 -> 141\.0\n")
        # Without a terminal nobody is asked about the pin of gnu-sed: it stays, and so does what it uses.
        self.assertEqual(self.section(outcome, f"Pinned in {at_target}")[1:], [
            f"  gnu-sed 4.9, newest 4.10: stays pinned. To upgrade it: `{brew} unpin gnu-sed`, then `{brew} upgrade "
            "--formula gnu-sed`",
            "  On a terminal and without --yes, `brew-ports plan` asks whether to remove each pin."])
        self.assertEqual(self.section(outcome, f"Not upgraded by --upgrade-all in {at_target}")[1:], [
            "  ddrescue: gnu-sed, which is pinned, uses it. To upgrade it all the same: "
            f"`{brew} upgrade --formula ddrescue`",
            "  docker-desktop (app): Homebrew asks for your password for its upgrade. To upgrade it: "
            f"`{brew} upgrade --cask docker-desktop`"])
        # What to know of the upgrades follows the table of them.
        self.assertIn("\n  firefox (app)  140.0 -> 141.0\n"
                      "  Homebrew may close an app that is open for its upgrade, and then opens it again.\n"
                      "  The old version of each upgraded formula stays installed; afterwards `brew-ports doctor` "
                      "offers to delete those versions.\n", text)
        self.assertIn("\n  3  Install the replacements and upgrade the other packages\n", text)
        # What the replacements need keeps its own table, with the reason of each.
        self.assertRegex(text, r"\n  openssl@3 +3\.5\.0 -> 3\.6\.0 +a dependency of wget\n")

    def test_a_yes_to_the_pin_upgrades_it_and_what_it_held_back(self):
        self.brew_host()
        ask = FakeAsk({"Remove the pin": "yes"})
        outcome = self.plan(ask=ask, upgrade_all=True)
        self.assert_exit(outcome, 0)
        plan, brew, at_target = outcome.plan, self.target.binary, f"Homebrew at {self.target.prefix}"
        self.assertEqual(len(ask.asked), 1)
        self.assertTrue(ask.asked[0].endswith(
            f"\ngnu-sed in {at_target} is pinned at 4.9; the newest version is 4.10.\n"
            "If you answer yes, the move removes the pin and upgrades it to 4.10. If you answer no, it stays as it "
            "is. --upgrade-all then leaves what it uses as it is, and every package whose upgrade needs a newer "
            "version of gnu-sed or of something it uses.\n"
            "Remove the pin and upgrade gnu-sed?"), ask.asked[0])
        acts = {a.action_id: a for a in actions(plan, 3)}
        self.assertEqual(list(acts)[:3], ["3.unpin.formulae", "3.upgrade.others", "3.upgrade.casks"])
        self.assertEqual(acts["3.unpin.formulae"].argv[2:], [brew, "unpin", "gnu-sed"])
        self.assertEqual(acts["3.upgrade.others"].argv[2:],
                         [brew, "upgrade", "--formula", "ddrescue", "gnu-sed", "openssl@3", "pkgconf"])
        self.assertEqual(plan.optional_upgrades, ["ddrescue", "gnu-sed", "pkgconf"])
        self.assertEqual(self.section(outcome, f"Pinned in {at_target}")[1:],
                         ["  gnu-sed 4.9 -> 4.10: the pin is removed and it is upgraded, as you answered",
                          "  `brew-ports rollback` does not put a removed pin back."])
        others = self.section(outcome, f"Other upgrades in {at_target}, as --upgrade-all asks")
        self.assertEqual([line.split()[0] for line in others[3:6]], ["ddrescue", "pkgconf", "firefox"])
        self.assertEqual(self.section(outcome, f"Not upgraded by --upgrade-all in {at_target}")[1:], [
            "  docker-desktop (app): Homebrew asks for your password for its upgrade. To upgrade it: "
            f"`{brew} upgrade --cask docker-desktop`"])

    def test_a_no_to_the_pin_is_said_to_be_the_users_answer(self):
        self.brew_host()
        at_target = f"Homebrew at {self.target.prefix}"
        outcome = self.plan(ask=FakeAsk({"Remove the pin": "no"}), upgrade_all=True)
        self.assert_exit(outcome, 0)
        self.assertEqual(len(self.section(outcome, f"Pinned in {at_target}")), 2)
        self.assertIn("  gnu-sed 4.9, newest 4.10: stays pinned, as you answered. To upgrade it: ", self.text(outcome))
        # --yes answers no question about a pin, and the report says how to be asked.
        unasked = self.plan(ask=FakeAsk({"Remove the pin": "yes"}, yes=True), upgrade_all=True)
        self.assertEqual(self.section(unasked, f"Pinned in {at_target}")[2],
                         "  On a terminal and without --yes, `brew-ports plan` asks whether to remove each pin.")
        self.assertNotIn("3.unpin.formulae", ids(unasked.plan, 3))

    def pins(self, *more, casks=None, **outdated):
        """Make a move of wget into a Homebrew with a pinned, outdated gnu-sed that uses ddrescue

        @param more      further packages of the target
        @param casks     the version each outdated cask upgrades to
        @param outdated  the version each further outdated formula upgrades to
        @returns         the target's `brew`
        """
        self.ports_source(port("wget", self.local, "1.25.0"))
        prefix = self.path("opt", "homebrew")
        versions = {"gnu-sed": "4.10", "ddrescue": "1.29"}
        versions.update(outdated)
        self.brew_target(formula("gnu-sed", prefix, version="4.9", outdated=True, pinned=True, deps=["ddrescue"]),
                         formula("ddrescue", prefix, version="1.28", outdated=True), *more,
                         payload=PAYLOAD, outdated_formulae=versions, outdated_casks=casks or {})
        return self.target.binary

    def test_what_a_kept_pin_holds_back_stays_with_its_command(self):
        prefix = self.path("opt", "homebrew")
        brew = self.pins(formula("gawk", prefix, version="5.3.0", outdated=True, deps=["gnu-sed"]),
                         formula("bat", prefix, version="0.24", outdated=True, deps=["ddrescue"]),
                         gawk="5.3.1", bat="0.25")
        outcome = self.plan(upgrade_all=True)
        self.assert_exit(outcome, 0)
        self.assertEqual([i for i in ids(outcome.plan, 3) if "upgrade" in i], [])
        self.assertEqual(self.section(outcome, f"Not upgraded by --upgrade-all in Homebrew at {prefix}")[1:], [
            "  bat: its upgrade would also upgrade ddrescue, which a pinned formula uses. To upgrade it all the same: "
            f"`{brew} upgrade --formula bat`",
            f"  ddrescue: gnu-sed, which is pinned, uses it. To upgrade it all the same: `{brew} upgrade --formula "
            "ddrescue`",
            f"  gawk: it needs the newest gnu-sed, which is pinned. To upgrade it: `{brew} unpin gnu-sed`, then "
            f"`{brew} upgrade --formula gawk`"])
        self.assertIn(f"\n--upgrade-all upgrades nothing more in Homebrew at {prefix}.\n", self.text(outcome))
        # A yes to the pin frees all four.
        freed = self.plan(ask=FakeAsk({"Remove the pin": "yes"}), upgrade_all=True)
        self.assertEqual(next(a.argv[-4:] for a in actions(freed.plan, 3) if a.action_id == "3.upgrade.others"),
                         ["bat", "ddrescue", "gawk", "gnu-sed"])
        self.assertEqual(self.section(freed, f"Not upgraded by --upgrade-all in Homebrew at {prefix}"), [])

    def test_a_pin_at_its_newest_version_is_asked_about(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("gnu-sed", prefix, version="4.10", pinned=True, deps=["ddrescue"]),
                         formula("ddrescue", prefix, version="1.28", outdated=True),
                         formula("node", prefix, version="26.12.0", pinned=True),
                         payload=PAYLOAD, outdated_formulae={"ddrescue": "1.29"})
        brew = self.target.binary
        ask = FakeAsk({"Remove the pin": "no"})
        kept = self.plan(ask=ask, upgrade_all=True)
        self.assert_exit(kept, 0)
        # node is pinned too, at its newest version, and holds nothing back: nobody is asked about it.
        self.assertEqual(len(ask.asked), 1)
        self.assertTrue(ask.asked[0].endswith(
            f"\ngnu-sed in Homebrew at {prefix} is pinned at 4.10, its newest version. --upgrade-all would upgrade "
            "ddrescue, which it uses.\n"
            "If you answer yes, the move removes the pin and upgrades that package. If you answer no, the pin stays "
            "and --upgrade-all leaves that package as it is.\n"
            "Remove the pin of gnu-sed?"), ask.asked[0])
        self.assertIn(f"  gnu-sed 4.10: stays pinned, as you answered. To remove the pin: `{brew} unpin gnu-sed`\n",
                      self.text(kept))
        self.assertIn("  ddrescue: gnu-sed, which is pinned, uses it. ", self.text(kept))
        freed = self.plan(ask=FakeAsk({"Remove the pin": "yes"}), upgrade_all=True)
        acts = {a.action_id: a for a in actions(freed.plan, 3)}
        self.assertEqual(acts["3.unpin.formulae"].argv[2:], [brew, "unpin", "gnu-sed"])
        self.assertEqual(acts["3.upgrade.others"].argv[2:], [brew, "upgrade", "--formula", "ddrescue"])
        self.assertIn("  gnu-sed 4.10: the pin is removed, as you answered\n", self.text(freed))

    def test_what_a_pin_holds_back_stays_beside_an_upgrade(self):
        self.brew_host()
        prefix = self.path("opt", "homebrew")
        # pkgconf is a replacement to upgrade; bat uses it and ddrescue, which the pinned gnu-sed keeps as it is.
        self.world.packages += [port("pkgconf", self.local, "2.5.1"),
                                formula("bat", prefix, version="0.24", outdated=True, deps=["pkgconf", "ddrescue"])]
        outcome = self.plan(upgrade_all=True)
        self.assert_exit(outcome, 0)
        acts = {a.action_id: a for a in actions(outcome.plan, 3)}
        self.assertEqual(acts["3.upgrade.formulae"].argv[-1], "pkgconf")
        # Left to itself, Homebrew would upgrade bat after pkgconf, and ddrescue with it.
        self.assertEqual({acts[i].env_profile for i in ("3.upgrade.formulae", "3.upgrade.others")},
                         {runner.BREW_NAMED_ONLY})
        self.assertNotIn("bat", acts["3.upgrade.others"].argv)
        text = self.text(outcome)
        self.assertIn("\n  Checked after the upgrades, and installed again if one lost a library: bat\n", text)
        self.assertIn("\n  bat: its upgrade would also upgrade ddrescue, which a pinned formula uses. ", text)
        self.assertNotIn("0.24 ->", text)

    def test_a_pinned_app_is_asked_about_like_a_pinned_formula(self):
        prefix = self.path("opt", "homebrew")
        brew = self.pins(cask("firefox", prefix, version="140.0", outdated=True, pinned=True),
                         cask("docker-desktop", prefix, version="4.40", outdated=True, pinned=True,
                              privileged_uninstall=True),
                         casks={"firefox": "141.0", "docker-desktop": "4.41"})
        ask = FakeAsk({"Remove the pin and upgrade firefox": "no"})
        kept = self.plan(ask=ask, upgrade_all=True)
        self.assert_exit(kept, 0)
        self.assertTrue(ask.asked[-1].endswith(
            f"firefox (app) in Homebrew at {prefix} is pinned at 140.0; the newest version is 141.0.\n"
            "If you answer yes, the move removes the pin and upgrades it to 141.0. If you answer no, it stays as it "
            "is.\nRemove the pin and upgrade firefox?"), ask.asked[-1])
        self.assertEqual(len(ask.asked), 2)                     # gnu-sed and firefox: the other app needs a password
        self.assertNotIn("3.upgrade.casks", ids(kept.plan, 3))
        self.assertIn("  firefox (app) 140.0, newest 141.0: stays pinned, as you answered. To upgrade it: "
                      f"`{brew} unpin --cask firefox`, then `{brew} upgrade --cask firefox`\n", self.text(kept))
        self.assertIn("  docker-desktop (app): it is pinned, and Homebrew asks for your password for its upgrade. To "
                      f"upgrade it: `{brew} unpin --cask "
                      f"docker-desktop`, then `{brew} upgrade --cask docker-desktop`\n", self.text(kept))
        freed = self.plan(ask=FakeAsk({"Remove the pin and upgrade firefox": "yes"}), upgrade_all=True)
        acts = {a.action_id: a for a in actions(freed.plan, 3)}
        self.assertEqual(list(acts)[:2], ["3.unpin.casks", "3.upgrade.casks"])
        self.assertEqual(acts["3.unpin.casks"].argv[2:], [brew, "unpin", "--cask", "firefox"])
        self.assertEqual(freed.plan.optional_casks, ["firefox"])
        self.assertIn("  firefox (app) 140.0 -> 141.0: the pin is removed and it is upgraded, as you answered\n",
                      self.text(freed))

    def test_a_command_for_an_intel_homebrew_keeps_its_arch(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        intel = instance(Manager.BREW, self.usr_local, arch="x86_64")
        self.target = self.world.add(
            intel, formula("gnu-sed", self.usr_local, version="4.9", outdated=True, pinned=True),
            cat=catalogue(self.tmp, PAYLOAD), outdated_formulae={"gnu-sed": "4.10"})
        outcome = self.plan(upgrade_all=True)
        self.assert_exit(outcome, 0)
        brew = f"arch -x86_64 {intel.binary}"
        self.assertIn(f"  gnu-sed 4.9, newest 4.10: stays pinned. To upgrade it: `{brew} unpin gnu-sed`, then `{brew} "
                      "upgrade --formula gnu-sed`\n", self.text(outcome))

    def test_a_version_that_homebrew_does_not_name_is_not_made_up(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("gnu-sed", prefix, version="4.9", outdated=True, pinned=True), payload=PAYLOAD)
        ask = FakeAsk({"Remove the pin": "no"})
        outcome = self.plan(ask=ask, upgrade_all=True)
        self.assertIn(f"\ngnu-sed in Homebrew at {prefix} is pinned at 4.9; a newer version exists.\n", ask.asked[0])
        self.assertIn("  gnu-sed 4.9: stays pinned, as you answered. To upgrade it: ", self.text(outcome))

    def test_the_option_says_so_when_it_adds_nothing(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        self.brew_target(formula("pkgconf", self.path("opt", "homebrew"), version="2.5.1"), payload=PAYLOAD)
        outcome = self.plan(upgrade_all=True)
        self.assert_exit(outcome, 0)
        self.assertIn(f"\n--upgrade-all upgrades nothing more in Homebrew at {self.target.prefix}.\n",
                      self.text(outcome))
        self.assertIn("\n  3  Install the replacements\n", self.text(outcome))

    def test_a_macports_target_upgrades_each_outdated_port(self):
        self.brew_source(formula("wget", self.usr_local, version="1.25.0"))
        self.ports_target(port("wget", self.local, "1.24.5", outdated=True),
                          port("zlib", self.local, "1.3", outdated=True, requested=False),
                          port("curl", self.local, "8.16.0", outdated=True), port("pipx", self.local, "1.18.11"))
        upgrades = [i for i in ids(self.plan().plan, 3) if i.startswith("3.upgrade")]
        self.assertEqual(upgrades, ["3.upgrade.wget"])
        outcome = self.plan(upgrade_all=True)
        self.assert_exit(outcome, 0)
        acts = {a.action_id: a for a in actions(outcome.plan, 3)}
        self.assertEqual([i for i in acts if i.startswith("3.upgrade")],
                         ["3.upgrade.wget", "3.upgrade.curl", "3.upgrade.zlib"])
        # What the option adds is upgraded so that no successor takes the place of a replaced port.
        self.assertEqual(acts["3.upgrade.curl"].argv[-4:], ["upgrade", "--no-replace", "--no-rev-upgrade", "curl"])
        self.assertEqual(acts["3.upgrade.wget"].argv[-3:], ["upgrade", "--no-rev-upgrade", "wget"])
        self.assertNotEqual(acts["3.upgrade.curl"].on_failure, OnFailure.STOP)
        self.assertEqual(outcome.plan.target_upgrades, ["wget", "curl", "zlib"])
        self.assertIn(f"\nOther upgrades in MacPorts at {self.local}, as --upgrade-all asks\n", self.text(outcome))


class Phase3BrewTest(PlannerCase):
    """The phase 3 actions of a Homebrew target"""

    def setUp(self):
        super().setUp()
        prefix = self.path("opt", "homebrew")
        self.ports_source(port("wget", self.local, "1.25.0"), port("dd_rescue", self.local, "1.29"),
                          port("gsed", self.local, "4.9"), port("nodejs26", self.local, "26.13.0"),
                          port("videolan-player", self.local, "3.0.21", homepage="https://www.videolan.org/vlc/"))
        self.brew_source(cask("firefox", self.usr_local), cask("docker", self.usr_local))
        self.brew_target(formula("gnu-sed", prefix, version="4.10", requested=False),
                         formula("node", prefix, version="26.12.0", outdated=True),
                         cask("docker-desktop", prefix))

    def test_the_actions_of_phase_3(self):
        plan = self.plan(maps=["dd_rescue=ddrescue"]).plan
        acts = {a.action_id: a for a in actions(plan, 3)}
        self.assertEqual(list(acts), ["3.upgrade.formulae", "3.install.bottled", "3.install.built",
                                      "3.install.casks", "3.adopt.firefox", "3.mark.gnu-sed"])
        brew = self.target.binary
        self.assertEqual(acts["3.upgrade.formulae"].argv[2:], [brew, "upgrade", "--formula", "node"])
        self.assertEqual(acts["3.install.bottled"].argv[2:], [brew, "install", "--formula", "wget"])
        self.assertEqual(acts["3.install.built"].argv[-1], "ddrescue")
        self.assertEqual(acts["3.install.casks"].argv[-1], "vlc")
        self.assertEqual(acts["3.adopt.firefox"].on_failure, OnFailure.RETRY_WITH)
        self.assertEqual(acts["3.adopt.firefox"].retry_argv[-2:], ["--force", "firefox"])
        self.assertEqual(acts["3.mark.gnu-sed"].argv[-2:], ["--installed-on-request", "gnu-sed"])
        for action in acts.values():
            self.assertEqual(action.env_profile, runner.BREW_NAMED_ONLY)
            self.assertFalse(action.sudo)
            self.assertNotEqual(action.on_failure, OnFailure.STOP, action.action_id)
        self.assertEqual(acts["3.install.bottled"].split_head, len(acts["3.install.bottled"].argv) - 1)
        self.assertEqual(plan.target_upgrades, ["node"])
        # docker is docker-desktop, which the target's Caskroom holds: adopted with no phase 3 action.
        self.assertIn(("cask-adopted", "docker"), plan.removal_set[self.usr_local])


class Phase3PortsTest(PlannerCase):
    """The phase 3 actions of a MacPorts target"""

    def test_the_actions_of_phase_3(self):
        self.brew_source(formula("wget", self.usr_local, version="1.25.0"),
                         formula("gnu-sed", self.usr_local, version="4.10",
                                 homepage="https://www.gnu.org/software/sed/"),
                         formula("pipx", self.usr_local, version="1.18.14"))
        self.ports_target(port("wget", self.local, "1.24.5", outdated=True), port("pipx", self.local, "1.18.11",
                                                                                  requested=False))
        plan = self.plan().plan
        acts = {a.action_id: a for a in actions(plan, 3)}
        self.assertEqual(list(acts), ["3.upgrade.wget", "3.install.gsed", "3.mark.pipx"])
        port_bin = self.target.binary
        self.assertEqual(acts["3.upgrade.wget"].argv[2:], [port_bin, "-N", "-t", "upgrade", "--no-rev-upgrade", "wget"])
        self.assertTrue(acts["3.upgrade.wget"].sudo)
        install = acts["3.install.gsed"]
        self.assertEqual(install.argv[2:], [port_bin, "-N", "-b", "install", "--no-rev-upgrade", "gsed"])
        self.assertEqual(install.on_failure, OnFailure.RETRY_WITH)
        self.assertEqual(install.retry_argv[2:], [port_bin, "-N", "-t", "install", "--no-rev-upgrade", "gsed"])
        self.assertEqual(acts["3.mark.pipx"].argv[-2:], ["setrequested", "pipx"])
        self.assertEqual(plan.target_upgrades, ["wget"])


class Phase2Test(PlannerCase):
    """The target repairs phase 2 takes from the findings"""

    def remedy(self, code, subject, step="reinstall"):
        """Return a `brew reinstall` remedy of the target, as `doctor` builds one

        @param code     the finding's code
        @param subject  the formula to reinstall
        @param step     the last part of the action id
        @returns        the action `doctor.<code>.<subject>.<step>`
        """
        return brew_actions.reinstall(self.target, "arm64", f"doctor.{code}.{subject}.{step}", [subject])

    def test_repairs_in_phase_2_order(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("openssl@3", prefix), formula("other", prefix), payload=PAYLOAD)
        linkage, receipt = "brew-broken-linkage", "brew-keg-without-receipt"
        issues = [
            doctor._issue(linkage, Severity.HIGH, "Broken linkage", "openssl@3", prefix, evidence=[],
                          remedies=[self.remedy(linkage, "openssl@3")], confirm_each=True, repairs_install=True),
            doctor._issue(receipt, Severity.HIGH, "Keg without receipt", "openssl@3", prefix, evidence=[],
                          remedies=[self.remedy(receipt, "openssl@3")], confirm_each=True, repairs_install=True),
            doctor._issue(linkage, Severity.HIGH, "Broken linkage", "other", prefix, evidence=[],
                          remedies=[self.remedy(linkage, "other")], confirm_each=True, repairs_install=True),
            doctor._issue(linkage, Severity.HIGH, "Broken linkage", "wget", self.local, evidence=[],
                          remedies=[self.remedy(linkage, "wget")], repairs_install=True),
        ]
        plan = self.plan(issues=issues).plan
        acts = actions(plan, 2)
        self.assertEqual([a.action_id for a in acts], ["2.brew-keg-without-receipt.openssl@3.reinstall",
                                                       "2.brew-broken-linkage.openssl@3.reinstall"])
        self.assertTrue(acts[0].description.startswith("brew-keg-without-receipt openssl@3: "))
        # A repair keeps Homebrew to the formula it names, as the commands of phase 3 do.
        self.assertEqual({a.env_profile for a in acts}, {runner.BREW_NAMED_ONLY})

    def test_what_a_repair_installs_counts_among_the_upgrades(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("wget", prefix, version="1.25.0", deps=["openssl@3"]),
                         formula("pkgconf", prefix, version="2.4.0", outdated=True, requested=False),
                         formula("ddrescue", prefix, version="1.29", deps=["pkgconf"]),
                         payload=dict(PAYLOAD, formulae=dict(PAYLOAD["formulae"], **{
                             "openssl@3": {"stable_version": "3.6.0", "stable_dependencies": ["pkgconf"]}})),
                         outdated_formulae={"pkgconf": "2.5.1"})
        missing = "brew-missing-dependency"
        install = brew_actions.install_formulae(self.target, "arm64", f"doctor.{missing}.wget.install", ["openssl@3"])
        issue = doctor._issue(missing, Severity.HIGH, "Missing dependency", "wget", prefix, evidence=[],
                              remedies=[install], repairs_install=True)
        outcome = self.plan(issues=[issue])
        self.assert_exit(outcome, 0)
        self.assertEqual(plan_phases.installed_by(actions(outcome.plan, 2)), ["openssl@3"])
        # Installing the missing openssl@3 may bring pkgconf up to date, which ddrescue uses too.
        self.assertEqual(outcome.plan.target_upgrades, ["pkgconf", "ddrescue"])
        self.assertRegex(self.text(outcome), r"\n  pkgconf +2\.4\.0 -> 2\.5\.1 +a dependency of openssl@3\n")


class RebuildTest(PlannerCase):
    """The target packages rebuilt because they link into what the plan removes"""

    def test_package_linked_into_a_removal_is_rebuilt(self):
        lib = self.local + "/lib/libz.1.dylib"
        self.world.files[self.local] = {("zlib", "@1.3_0"): [(lib, True)]}
        self.ports_source(port("wget", self.local, "1.25.0", deps=["zlib"]),
                          port("zlib", self.local, "1.3", requested=False))
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("tool", prefix), formula("keeper", prefix))
        binary = prefix + "/Cellar/tool/1.0/bin/tool"
        self.world.linkage = {"binaries": {
            binary: {"package": f"{prefix}|formula|tool", "instance_prefix": prefix,
                     "references": [{"name": lib, "resolved": lib, "class": "other"}]},
            prefix + "/Cellar/keeper/1.0/bin/keeper": {
                "package": f"{prefix}|formula|keeper", "instance_prefix": prefix,
                "references": [{"name": "/usr/lib/libSystem.B.dylib", "resolved": "/usr/lib/libSystem.B.dylib",
                                "class": "system"}]}}}
        plan = self.plan().plan
        rebuild = next(a for a in actions(plan, 3) if a.action_id == "3.tool.rebuild")
        self.assertEqual(rebuild.argv[-3:], ["reinstall", "--formula", "tool"])
        self.assertEqual(rebuild.on_failure, OnFailure.PROBE)
        self.assertNotIn("3.keeper.rebuild", ids(plan, 3))
        kept = self.plan(keep=["zlib"])
        self.assertNotIn("3.tool.rebuild", ids(kept.plan, 3))
        self.assertIn(f"  tool ({binary}) still uses {lib}, which stays: nothing to do", kept.report)

    def test_what_a_rebuilt_formula_needs_is_listed_as_an_upgrade(self):
        lib = self.local + "/lib/libz.1.dylib"
        self.world.files[self.local] = {("zlib", "@1.3_0"): [(lib, True)]}
        self.ports_source(port("wget", self.local, "1.25.0", deps=["zlib"]),
                          port("zlib", self.local, "1.3", requested=False))
        prefix = self.path("opt", "homebrew")
        self.brew_target(formula("tool", prefix, deps=["pcre2"]),
                         formula("pcre2", prefix, version="10.44", outdated=True, requested=False),
                         formula("grep", prefix, version="3.11", deps=["pcre2"]),
                         outdated_formulae={"pcre2": "10.45"})
        self.world.linkage = {"binaries": {prefix + "/Cellar/tool/1.0/bin/tool": {
            "package": f"{prefix}|formula|tool", "instance_prefix": prefix,
            "references": [{"name": lib, "resolved": lib, "class": "other"}]}}}
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertIn("3.tool.rebuild", ids(outcome.plan, 3))
        # `brew reinstall tool` may bring pcre2 up to date. Homebrew does not look after grep, which uses pcre2
        # too, so the plan names both: phase 3 checks grep and installs it again if it lost a library.
        self.assertEqual(outcome.plan.target_upgrades, ["pcre2", "grep", "tool"])
        self.assertRegex(self.text(outcome), r"\n  pcre2 +10\.44 -> 10\.45 +a dependency of tool\n"
                                             r"  Checked after the upgrades, and installed again if one lost a "
                                             r"library: grep, tool\n")

    def test_a_link_into_a_rack_under_an_old_name_is_rebuilt(self):
        keg = self.usr_local + "/Cellar/oldwget/1.25.0"
        lib = keg + "/lib/libwget.1.dylib"
        self.brew_source(formula("wget", self.usr_local, version="1.25.0"), kegs={"wget": [keg]})
        self.ports_target(port("tool", self.local, "1.0"))
        self.world.linkage = {"binaries": {self.local + "/bin/tool": {
            "package": f"{self.local}|port|tool", "instance_prefix": self.local,
            "references": [{"name": lib, "resolved": lib, "class": "other"}]}}}
        outcome = self.plan()
        self.assertIn("3.tool.rebuild", ids(outcome.plan, 3), self.text(outcome))


class Phase6Test(PlannerCase):
    """The phase 6 previews of the old installations a plan uninstalls"""

    def test_previews_of_a_macports_instance(self):
        src = self.local
        for sub in ("var/db/mysql8", "var/macports/registry", "var/log", "etc/macports"):
            os.makedirs(os.path.join(src, sub), exist_ok=True)
        with open(os.path.join(src, "etc", "macports", "macports.conf"), "w", encoding="utf-8") as fh:
            fh.write(f"prefix {src}\n")
        self.ports_source(port("wget", src, "1.25.0"), portdbpath=src + "/var/macports",
                          applications_dir="/Applications/MacPorts")
        self.world.services.append(service("org.macports.mysql8", "/Library/LaunchDaemons/org.macports.mysql8.plist",
                                           src, package="mysql8", kind="port", scope="system"))
        self.brew_target()
        plan = self.plan().plan
        acts = actions(plan, 6)
        by_id = {a.action_id: a for a in acts}
        self.assertTrue(all(a.manual for a in acts))
        archive = by_id[f"6.archive.{(src + '/var/db').replace('/', '%')}"]
        self.assertEqual(archive.argv, ["/usr/bin/tar", "-czf", "-", "-C", "/", (src + "/var/db").lstrip("/")])
        self.assertTrue(archive.sudo)
        self.assertIn(f"6.archive.{(src + '/etc').replace('/', '%')}", by_id)
        self.assertNotIn(f"6.archive.{(src + '/var/macports').replace('/', '%')}", by_id)
        self.assertNotIn(f"6.archive.{(src + '/var/log').replace('/', '%')}", by_id)
        deleted = [a.argv[-1] for a in acts if a.action_id.startswith("6.delete.")]
        self.assertEqual(deleted[:3],
                         [src, "/Applications/MacPorts", "/Library/LaunchDaemons/org.macports.mysql8.plist"])
        self.assertNotIn(self.target.prefix, " ".join(deleted))
        self.assertEqual(plan.path_removed, {})
        self.assertEqual(plan.removal_set, {src: [("port", "wget")]})

    def test_prefix_without_marker_is_never_deleted(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        self.brew_target()
        self.unmark(self.local)
        plan = self.plan().plan
        self.assertEqual(actions(plan, 6), [])
        self.assertEqual((plan.options["remove_manager"], [p.number for p in plan.phases]),
                         ("", [0, 1, 2, 3, 4, 5, 7, 8]))

    def test_previews_of_a_homebrew_instance(self):
        prefix = self.usr_local
        for sub in ("Cellar/wget/1.25.0", "Homebrew/Library/Taps/homebrew", "var/homebrew/linked", "etc", "bin"):
            os.makedirs(os.path.join(prefix, sub), exist_ok=True)
        with open(os.path.join(prefix, "bin", "brew"), "w"):
            pass
        self.brew_source(formula("wget", prefix, version="1.25.0"), repository=prefix + "/Homebrew")
        self.brew_target()
        with mock.patch("brew_ports.homebrew.locate.USR_LOCAL", prefix):
            acts = actions(self.plan().plan, 6)
        deleted = [a.argv[-1] for a in acts if a.action_id.startswith("6.delete.")]
        self.assertEqual(deleted, [prefix + "/Homebrew", prefix + "/Cellar", prefix + "/bin/brew",
                                   prefix + "/var/homebrew"])
        archived = [a.argv[-1] for a in acts if a.action_id.startswith("6.archive.")]
        self.assertEqual(archived, [(prefix + p).lstrip("/") for p in ("/var", "/etc", "/Homebrew/Library/Taps")])
        # Other installers share /usr/local, and the target is a Homebrew that survives: no notes of what goes last.
        notes = [a.action_id for a in acts if a.kind == "note"]
        self.assertEqual(notes, [f"6.note.{prefix.replace('/', '%')}.{n}" for n in ("checks", "repository", "links")])

    def test_previews_of_a_dedicated_prefix_and_the_shared_caches(self):
        prefix = self.path("opt", "homebrew")
        for sub in ("Cellar/wget/1.25.0", "Library/Taps/homebrew", "var/homebrew/linked", "var/postgresql@16",
                    "etc/openssl@3", "bin"):
            os.makedirs(os.path.join(prefix, sub), exist_ok=True)
        with open(os.path.join(prefix, "bin", "brew"), "w"):
            pass
        home, library = self.path("Users", "alice"), self.path("Library")
        caches = [os.path.join(home, "Library", "Caches", "Homebrew"), os.path.join(library, "Caches", "Homebrew"),
                  os.path.join(home, ".cache", "Homebrew")]
        for path in caches:
            os.makedirs(path)
        self.brew_source(formula("wget", prefix, version="1.25.0"), prefix=prefix)
        self.ports_target()
        with mock.patch("brew_ports.plan_phases.SYSTEM_LIBRARY", library):
            outcome = self.plan(environ={"HOME": home})
        self.assert_exit(outcome, 0)
        acts = actions(outcome.plan, 6)
        tag = prefix.replace("/", "%")
        notes = {a.action_id: a.description for a in acts if a.kind == "note"}
        self.assertEqual(notes[f"6.note.{tag}.remaining"], (
            f"then `apply` asks again (--yes answers) before it saves in the run folder and deletes whatever is left "
            f"in {prefix}; a no keeps {prefix} with it; besides the paths above it holds bin, etc, var as this plan "
            "is made"))
        self.assertEqual(notes[f"6.note.{tag}.prefix"], f"then {prefix} itself (rm -d), once nothing is left in it")
        self.assertEqual((acts[-1].action_id, acts[-1].description), (
            f"6.note.{tag}.caches", "last, when no Homebrew is left on this Mac, the caches and logs that all "
            f"Homebrew installations share are deleted, without a saved copy: {', '.join(caches)}"))
        self.assertFalse([text for text in notes.values() if "<run>" in text])

    def test_phase_6_only_when_an_instance_goes(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        self.brew_target()
        self.assertEqual([p.number for p in self.plan(keep_managers=True).plan.phases], [0, 1, 2, 3, 4, 5, 7, 8])
        phases = self.plan().plan.phases
        self.assertEqual([p.number for p in phases], [0, 1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual([p.number for p in phases if p.confirm], [1, 2, 3, 5, 6, 7])
        self.assertEqual([p.actions for p in phases if p.number in (0, 1, 4, 5, 7, 8)], [[]] * 6)
        self.assertEqual([p.name for p in phases], [
            "checks before starting", "save a record for undo", "repair the installation that stays",
            "install the replacements", "check the replacements", "uninstall the old packages",
            "uninstall the old managers", "clean up the shell files", "final check"])


class UnsafeTest(PlannerCase):
    """The paths phase 6 must never delete"""

    def test_the_safety_rules(self):
        target = self.brew_target()
        home = "/Users/alice"
        self.assertIsNotNone(plan_phases.unsafe(target.prefix + "/Cellar", target, home))
        for path in ("/", "/usr/local", "/Applications", "/Users", home, "/Users/alice/../alice"):
            self.assertIsNotNone(plan_phases.unsafe(path, target, home), path)
        self.assertIsNone(plan_phases.unsafe(self.local, target, home))


class InstallsTest(unittest.TestCase):
    """The target packages phase 3 installs: each mapping's target, then its companions, each once"""

    def test_a_companion_is_installed_beside_its_target_once(self):
        mappings = [Mapping(source=formula(source, "/opt/homebrew"), target_kind="port", target_name=target,
                            target_version=None, confidence=Confidence.EXACT, evidence=[], companions=companions,
                            selections=[], variants_note=None)
                    for source, target, companions in (("tcl-tk", "tcl", ["tk"]), ("tk-tools", "tk", []))]
        installs, projects = plan_phases.installs(mappings)
        self.assertEqual([(i.kind, i.name) for i in installs], [("port", "tcl"), ("", "tk")])
        self.assertEqual(projects, [])


if __name__ == "__main__":
    unittest.main()

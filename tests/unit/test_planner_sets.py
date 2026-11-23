"""The kept and removal sets: casks, `--only`, undrivable sources, the login shell, files outside a prefix"""

import os
import unittest

from brew_ports import model, plan_sets, report
from brew_ports.model import Usability
from tests.unit.fixtures.doctor.builders import service
from tests.unit.fixtures.planner.builders import (BREW, PORTS, FakeAsk, PlannerCase, actions, cask, formula, instance,
                                                  port)
from tests.unit.helpers import TempDirTest

CONDA = "/Users/alice/miniconda-base"


def names(packages):
    """Return the names of packages, sorted

    @param packages  the packages
    @returns         their names
    """
    return sorted(p.name for p in packages)


class ChainTest(PlannerCase):
    """A dependency chain under a plain plan, a kept root and a kept dependency"""

    def setUp(self):
        super().setUp()
        src = self.local
        self.ports_source(port("wget", src, "1.25.0", deps=["libidn2"]),
                          port("libidn2", src, "2.3", requested=False, deps=["libunistring"]),
                          port("libunistring", src, "1.3", requested=False))
        self.brew_target()

    def test_a_dependency_chain(self):
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.removal_set, {self.local: [("port", "libidn2"), ("port", "libunistring"),
                                                                 ("port", "wget")]})
        self.assertEqual(outcome.plan.kept, [])

    def test_a_kept_root_keeps_its_closure(self):
        outcome = self.plan(keep=["wget"])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.removal_set, {})
        self.assertEqual(names(outcome.plan.kept), ["libidn2", "libunistring", "wget"])
        title = f"Staying in MacPorts at {self.local}"
        self.assertEqual(self.section(outcome, title), [
            title, "  wget 1.25.0: you asked to leave it there (--leave)",
            "  and 2 packages it needs: libidn2, libunistring"])

    def test_a_kept_dependency(self):
        outcome = self.plan(keep=["libidn2"])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.removal_set, {self.local: [("port", "wget")]})
        self.assertEqual(names(outcome.plan.kept), ["libidn2", "libunistring"])
        self.assertEqual([m.target_name for m in outcome.plan.mappings], ["wget"])


class VersionsTest(PlannerCase):
    """A port's inactive and active versions as one unit"""

    def test_inactive_and_active_versions_are_one_root(self):
        self.ports_source(port("wget", self.local, "1.24.5", active=False), port("wget", self.local, "1.25.0"))
        self.brew_target()
        plan = self.plan().plan
        self.assertEqual([(p.name, p.version, p.active) for p in plan.roots], [("wget", "1.25.0_0", True)])
        self.assertEqual(plan.removal_set, {self.local: [("port", "wget")]})

    def test_an_imaged_only_port_with_an_active_dependent(self):
        self.ports_source(port("libold", self.local, "1.0", active=False, requested=False),
                          port("wget", self.local, "1.25.0", deps=["libold"]))
        self.brew_target()
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(names(outcome.plan.kept), ["libold"])
        title = f"Staying in MacPorts at {self.local}"
        self.assertEqual(self.section(outcome, title), [
            title, "  libold 1.0: installed but switched off; `--uninstall libold` uninstalls it"])
        self.assertEqual(outcome.plan.removal_set, {self.local: [("port", "wget")]})
        self.assertEqual(outcome.plan.options["remove_manager"], "")
        self.assertIn(f"  MacPorts at {self.local} stays installed, because it keeps libold", outcome.report)
        dropped = self.plan(drop=["libold"]).plan
        self.assertEqual(dropped.removal_set, {self.local: [("port", "libold"), ("port", "wget")]})
        self.assertEqual(dropped.kept, [])


class OnlyTest(PlannerCase):
    """`--only`: the named units, the sweep of their dependencies, and an outside dependent"""

    def setUp(self):
        super().setUp()
        src = self.local
        self.ports_source(port("wget", src, "1.25.0", deps=["gsed", "libidn2", "libsvc"]),
                          port("gsed", src, "4.9"),
                          port("libidn2", src, "2.3", requested=False),
                          port("libsvc", src, "1.0", requested=False),
                          port("other", src, "1.0", deps=["libidn2"]))
        self.world.services.append(service("org.macports.libsvc", "/Library/LaunchDaemons/org.macports.libsvc.plist",
                                           src, package="libsvc", kind="port", scope="system"))
        self.brew_target()

    def test_only_with_an_outside_dependent_exits_1(self):
        outcome = self.plan(only=["gsed"])
        self.assert_exit(outcome, 1)
        self.assertIn(f"    gsed cannot be uninstalled from MacPorts at {self.local}: wget needs it, and is not in "
                      "--only. Add wget to --only, or take gsed out", outcome.problems)

    def test_only_sweeps_unneeded_dependencies(self):
        self.world.packages = [p for p in self.world.packages if p.name != "other"]
        outcome = self.plan(only=["wget"])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.removal_set, {self.local: [("port", "libidn2"), ("port", "wget")]})
        title = "Good to know"
        self.assertEqual(self.section(outcome, title), [
            title, f"  gsed stays in MacPorts at {self.local}: you installed it yourself",
            f"  libsvc stays in MacPorts at {self.local}: it has the service org.macports.libsvc"])
        self.assertEqual([p.name for p in outcome.plan.roots], ["wget"])

    def test_only_leaves_a_shared_dependency(self):
        outcome = self.plan(only=["wget"])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.removal_set, {self.local: [("port", "wget")]})

    def test_only_with_a_kept_dependency(self):
        self.world.packages = [p for p in self.world.packages if p.name != "other"]
        outcome = self.plan(only=["wget"], keep=["libidn2"])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.removal_set, {self.local: [("port", "wget")]})
        self.assertEqual(names(outcome.plan.kept), ["libidn2"])


class CasksForPortsTest(PlannerCase):
    """Casks under a MacPorts target: the cask policies `keep`, `drop` and `map`, manual casks, data casks"""

    def test_a_cask_depending_on_a_formula(self):
        self.brew_source(cask("vlc", self.usr_local, deps=["libfoo"]), formula("libfoo", self.usr_local,
                                                                            requested=False))
        self.ports_target()
        dropped = self.plan(casks="drop")
        self.assert_exit(dropped, 0)
        self.assertEqual(dropped.plan.removal_set, {self.usr_local: [("cask", "vlc"), ("formula", "libfoo")]})
        self.assertEqual(dropped.plan.roots, [])
        title = "An app to uninstall; to have it again, install it from its homepage"
        self.assertEqual(self.section(dropped, title), [title, "  vlc: no homepage is recorded"])
        self.assertIn("  1 formula, 1 cask, 1 of them a dependency", dropped.report)
        kept = self.plan()
        self.assert_exit(kept, 0)
        self.assertEqual(kept.plan.removal_set, {})
        self.assertEqual(names(kept.plan.kept), ["libfoo", "vlc"])
        title = f"Staying in Homebrew at {self.usr_local}"
        self.assertEqual(self.section(kept, title), [
            title, f"  vlc 1.0: {plan_sets.KEPT_APP}", "  and 1 package it needs: libfoo"])

    def test_kept_cask_needing_a_removed_cask_exits_1(self):
        self.brew_source(cask("miniconda", self.usr_local, caskroom_data=[CONDA]),
                         cask("kept-app", self.usr_local, cask_deps=["miniconda"]))
        self.ports_target()
        outcome = self.plan(drop=["miniconda"])
        self.assert_exit(outcome, 1)
        self.assertEqual(len(outcome.problems), 3)
        self.assertEqual(outcome.problems[1], (
            f"    miniconda cannot be uninstalled from Homebrew at {self.usr_local}: kept-app needs it, and kept-app "
            f"stays ({plan_sets.KEPT_APP}). To plan this move, take miniconda out of --uninstall"))
        title = "To uninstall without a replacement"
        self.assertEqual(self.section(outcome, title), [
            title, f"  miniconda 1.0 (Homebrew at {self.usr_local}): as you asked (--uninstall); its data in {CONDA} "
                   "will be deleted with it"])
        unasked = self.plan(drop=["kept-app"])
        self.assert_exit(unasked, 2)
        self.assertEqual(unasked.problems, [f"brew-ports: --uninstall kept-app: kept-app is an app, and "
                                            f"{plan_sets.KEPT_APP}"])

    def test_manual_cask_needing_a_removed_cask_exits_1(self):
        self.brew_source(cask("helper", self.usr_local),
                         cask("rooted", self.usr_local, cask_deps=["helper"], privileged_uninstall=True))
        self.ports_target()
        outcome = self.plan(casks="drop")
        self.assert_exit(outcome, 1)
        self.assertIn(f"    helper cannot be uninstalled from Homebrew at {self.usr_local}: rooted needs it, and only "
                      f"you can uninstall rooted. Run `{self.usr_local}/bin/brew uninstall --cask rooted` first, or "
                      "leave helper where it is too (`--leave helper`)", outcome.problems)
        title = f"Staying in Homebrew at {self.usr_local}"
        self.assertEqual(self.section(outcome, title), [
            title, "  rooted: only you can uninstall it; the command is below"])

    def test_removed_cask_needing_a_kept_cask_passes(self):
        self.brew_source(cask("base-app", self.usr_local), cask("plugin", self.usr_local, cask_deps=["base-app"]))
        self.ports_target()
        outcome = self.plan(casks="drop", keep=["base-app"])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.removal_set, {self.usr_local: [("cask", "plugin")]})
        self.assertEqual(names(outcome.plan.kept), ["base-app"])

    def privileged_source(self):
        """Add a Homebrew source with a cask that needs sudo to uninstall, its formula, and wget"""
        self.brew_source(cask("rooted", self.usr_local, deps=["libfoo"], privileged_uninstall=True),
                         formula("libfoo", self.usr_local, requested=False), formula("wget", self.usr_local))
        self.ports_target()

    def held(self, how="the command is below"):
        """Return what keeps the source of `privileged_source` installed, as the plan words it

        @param how  what the brackets hold: where the command is, or the command
        @returns    the clause about the cask only the user can uninstall
        """
        return f"it holds rooted, which only you can uninstall ({how})"

    def test_privileged_cask_is_a_manual_cask(self):
        self.privileged_source()
        outcome = self.plan(casks="drop")
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual(plan.manual_casks, ["rooted"])
        self.assertEqual(plan.removal_set, {self.usr_local: [("formula", "wget")]})
        self.assertEqual(names(plan.kept), ["libfoo"])
        self.assertIn(f"  {self.usr_local}/bin/brew uninstall --cask rooted", outcome.report)
        self.assertIn(f"  Homebrew at {self.usr_local} stays installed, because {self.held()}", outcome.report)

    def test_a_manual_cask_refuses_delete(self):
        self.privileged_source()
        refused = self.plan(casks="drop", delete=[self.usr_local])
        self.assert_exit(refused, 1)
        command = f"`{self.usr_local}/bin/brew uninstall --cask rooted`, then plan again"
        self.assertIn(f"    --delete {self.usr_local}: Homebrew at {self.usr_local} cannot be deleted while "
                      f"{self.held(command)}. Settle what stays in it, or plan without --delete", refused.problems)
        self.assertIn(f"  Homebrew at {self.usr_local} stays installed although --delete names it: {self.held()}",
                      refused.report)
        title = f"Staying in Homebrew at {self.usr_local}"
        self.assertEqual(self.section(refused, title), [
            title, "  rooted: only you can uninstall it; the command is below", "  and 1 package it needs: libfoo"])

    def test_casks_map_falls_back_to_drop(self):
        self.brew_source(cask("firefox", self.usr_local, version="145.0", homepage="https://www.mozilla.org/firefox/"),
                         cask("vlc", self.usr_local, homepage="https://www.videolan.org/vlc/"))
        self.ports_target()
        ask = FakeAsk()
        outcome = self.plan(casks="map", ask=ask)
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual([(m.source.name, m.target_name) for m in plan.mappings], [("firefox", "firefox-app")])
        self.assertEqual(plan.removal_set, {self.usr_local: [("cask", "firefox"), ("cask", "vlc")]})
        self.assertEqual(plan.kept, [])
        self.assertEqual(ask.asked, [])
        title = "To uninstall without a replacement"
        self.assertEqual(self.section(outcome, title), [
            title, f"  vlc 1.0 (Homebrew at {self.usr_local}): --casks replace uninstalls it: nothing of that name, or "
                   "like it, is in MacPorts' package list; to have it again, install it from "
                   "https://www.videolan.org/vlc/"])

    def test_an_unanswered_closest_port_leaves_the_app(self):
        self.brew_source(cask("vlc", self.usr_local, version="3.0.21", homepage="https://www.videolan.org/vlc/"))
        self.ports_target(add=[{"name": "vlc-app", "version": "2.2.8", "homepage": "https://www.videolan.org/vlc/"}])
        outcome = self.plan(casks="map")
        self.assert_exit(outcome, 0)
        self.assertEqual((outcome.plan.removal_set, names(outcome.plan.kept)), ({}, ["vlc"]))
        title = f"Staying in Homebrew at {self.usr_local}"
        self.assertEqual(self.section(outcome, title)[:2], [
            title, "  vlc 3.0.21: its closest match, port vlc-app, needs your yes: plan on a terminal without --yes, "
                   "or with --accept-closest or `--replace vlc=vlc-app`"])
        ask = FakeAsk({"to replace it?": "no"})
        declined = self.plan(casks="map", ask=ask)
        self.assertEqual(len(ask.asked), 2)
        self.assertIn(f"Keep it in Homebrew at {self.usr_local}, or drop it", ask.asked[1])
        self.assertEqual(declined.plan.removal_set, {})
        dropped = self.plan(casks="map", ask=FakeAsk({"to replace it?": "no", "Keep it in": "drop"}))
        self.assertEqual(dropped.plan.removal_set, {self.usr_local: [("cask", "vlc")]})
        taken = self.plan(casks="map", ask=FakeAsk({"to replace it?": "yes"}))
        self.assertEqual([(m.source.name, m.target_name) for m in taken.plan.mappings], [("vlc", "vlc-app")])

    def test_only_limits_the_cask_policy(self):
        self.brew_source(formula("wget", self.usr_local), cask("vlc", self.usr_local), cask("zoom", self.usr_local))
        self.ports_target()
        plan = self.plan(only=["wget", "zoom"], casks="drop").plan
        self.assertEqual(plan.removal_set, {self.usr_local: [("cask", "zoom"), ("formula", "wget")]})

    def test_data_cask_stays_unless_dropped(self):
        self.brew_source(cask("miniconda", self.usr_local, caskroom_data=[CONDA]), cask("vlc", self.usr_local))
        self.ports_target()
        for policy in ("keep", "drop", "map"):
            plan = self.plan(casks=policy).plan
            self.assertIn("miniconda", names(plan.kept), policy)
            self.assertEqual((plan.options["remove_manager"], [p.number for p in plan.phases if p.number == 6]),
                             ("", []), policy)
            self.assertIn(f"it keeps data in {CONDA}, which uninstalling it would delete",
                          [m.evidence[0] for m in plan.unmigratable], policy)
        plan = self.plan(casks="drop", drop=["miniconda"]).plan
        self.assertEqual(plan.removal_set, {self.usr_local: [("cask", "miniconda"), ("cask", "vlc")]})


class CasksForBrewTest(PlannerCase):
    """Casks under a Homebrew target: adoption, data casks, refused targets, manual casks"""

    def setUp(self):
        super().setUp()
        self.brew_source(cask("firefox", self.usr_local), cask("miniconda", self.usr_local, caskroom_data=[CONDA]),
                         cask("1kc-razer", self.usr_local),
                         cask("virtualbox", self.usr_local, privileged_uninstall=True))
        self.brew_target()

    def test_adoption_data_casks_and_refused_targets(self):
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual([(m.source.name, m.adopt) for m in plan.mappings], [("firefox", True)])
        self.assertEqual(plan.removal_set, {self.usr_local: [("cask-adopted", "firefox")]})
        reasons = {m.source.name: m.evidence[0] for m in plan.unmigratable}
        self.assertEqual(reasons["miniconda"], f"it keeps data in {CONDA}, which uninstalling it would delete")
        self.assertTrue(reasons["1kc-razer"].startswith("Homebrew has disabled 1kc-razer"))
        self.assertTrue(reasons["virtualbox"].startswith("Homebrew has it, but its installer asks for your password"))
        self.assertEqual(names(plan.kept), ["1kc-razer", "miniconda", "virtualbox"])
        self.assertEqual([a.action_id for a in actions(plan, 3)], ["3.adopt.firefox"])

    def test_dropped_sudo_cask_is_a_manual_cask(self):
        ask = FakeAsk({"virtualbox": "drop", "1kc-razer": "drop"})
        outcome = self.plan(ask=ask)
        plan = outcome.plan
        self.assertEqual(plan.manual_casks, ["virtualbox"])
        self.assertTrue(next(q for q in ask.asked if "virtualbox" in q).endswith(
            "or drop it (the plan then gives you the command to uninstall it, since Homebrew asks for your "
            "password)?"))
        title = "To uninstall without a replacement"
        self.assertEqual([line.split()[0] for line in self.section(outcome, title)[1:]], ["1kc-razer"])
        self.assertIn("  virtualbox: only you can uninstall it; the command is below", outcome.report)
        self.assertEqual(plan.removal_set, {self.usr_local: [("cask-adopted", "firefox"), ("cask", "1kc-razer")]})
        self.assertEqual(names(plan.kept), ["miniconda"])
        self.assertFalse(any("miniconda" in q for q in ask.asked))

    def test_adopted_casks_stay_and_are_not_listed_as_uninstalled(self):
        self.world.packages.append(formula("wget", self.usr_local))
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        where = f"Homebrew at {self.target.prefix}"
        self.assertIn(f"  1 app stays where it is; {where} takes over its record: firefox", outcome.report)
        title = f"To uninstall from Homebrew at {self.usr_local}"
        self.assertEqual(self.section(outcome, title), [title, "  1 formula", "      wget"])
        self.world.packages.append(cask("vlc", self.usr_local))
        outcome = self.plan()
        self.assertIn(f"  2 apps stay where they are; {where} takes over their record: firefox, vlc", outcome.report)
        self.assertEqual(self.section(outcome, title), [title, "  1 formula", "      wget"])


class UndrivableTest(PlannerCase):
    """A source whose command cannot run: left as it is, or deleted by path when `--delete` names it"""

    def setUp(self):
        super().setUp()
        self.brew_source(formula("wget", self.usr_local), cask("firefox", self.usr_local),
                         drivable=False, usability=Usability.CANNOT_RUN)
        self.brew_target()

    def test_a_full_move_leaves_it_as_it_is(self):
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual(names(plan.left_in_place), ["firefox", "wget"])
        self.assertEqual((plan.removal_set, plan.path_removed), ({}, {}))
        self.assertEqual(sorted(m.source.name for m in plan.mappings), ["firefox", "wget"])
        self.assertNotIn(6, [p.number for p in plan.phases])
        self.assertEqual(plan.options["remove_manager"], "")
        self.assertIn(f"  Homebrew at {self.usr_local} stays installed, since nothing can be uninstalled from it "
                      "(`brew-ports doctor` says why its command cannot run); "
                      f"`--delete {self.usr_local}` deletes it whole after the move", outcome.report)
        title = f"Staying in Homebrew at {self.usr_local}, whose `brew` command cannot run"
        self.assertEqual(self.section(outcome, title), [title, "  2 packages: firefox, wget"])

    def test_nothing_of_it_can_be_uninstalled_so_drop_is_not_offered(self):
        self.world.packages.append(formula("xyzzy", self.usr_local))
        ask = FakeAsk()
        outcome = self.plan(ask=ask)
        self.assert_exit(outcome, 0)
        self.assertEqual(ask.asked, [])
        self.assertNotIn("To uninstall without a replacement", outcome.report)
        title = f"Staying in Homebrew at {self.usr_local}, whose `brew` command cannot run"
        self.assertEqual(self.section(outcome, title), [title, "  3 packages: firefox, wget, xyzzy"])
        refused = self.plan(drop=["xyzzy"])
        self.assert_exit(refused, 2)
        self.assertEqual(refused.problems, [
            f"brew-ports: --uninstall xyzzy: nothing can be uninstalled from Homebrew at {self.usr_local}, because "
            f"its `brew` command cannot run. `--delete {self.usr_local}` deletes it whole after the move"])

    def test_delete_deletes_it_by_path(self):
        outcome = self.plan(delete=[self.usr_local])
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual(plan.path_removed, {self.usr_local: [("cask-adopted", "firefox"), ("formula", "wget")]})
        self.assertEqual(plan.removal_set, {})
        self.assertEqual(plan.left_in_place, [])
        self.assertIn(6, [p.number for p in plan.phases])
        self.assertEqual({a.action_id for a in actions(plan, 3)}, {"3.install.bottled", "3.adopt.firefox"})
        self.assertIn(f"  then uninstalling Homebrew at {self.usr_local}", outcome.report)
        title = f"To delete with Homebrew at {self.usr_local}, whose `brew` command cannot run"
        self.assertEqual(self.section(outcome, title), [title, "  1 formula: wget"])

    def test_under_only_it_stays_in_place(self):
        outcome = self.plan(only=["wget"])
        self.assert_exit(outcome, 0)
        self.assertEqual(names(outcome.plan.left_in_place), ["firefox", "wget"])
        self.assertEqual([m.target_name for m in outcome.plan.mappings], ["wget"])

    def test_unknown_packages_leave_it_as_it_is(self):
        self.world.instances[0].inventory_known = False
        self.world.packages = []
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertNotIn(6, [p.number for p in outcome.plan.phases])
        self.assertEqual(outcome.plan.options["remove_manager"], "")
        self.assertIn(f"  Homebrew at {self.usr_local} stays installed: brew-ports cannot read its record of "
                      "installed packages (`brew-ports doctor` says why)", outcome.report)
        # An installation whose packages are unknown is not one that holds none.
        self.assertNotIn("no packages", outcome.report[1])


class UnreadableTest(PlannerCase):
    """A Homebrew whose package folder cannot be read is not known to be empty"""

    @unittest.skipIf(os.geteuid() == 0, "root lists any directory")
    def test_it_stays_installed_and_its_packages_are_unknown(self):
        self.brew_source()
        self.ports_source(port("wget", self.local, "1.25.0"))
        self.brew_target()
        cellar = os.path.join(self.usr_local, "Cellar")
        os.chmod(cellar, 0)
        self.addCleanup(os.chmod, cellar, 0o755)
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.options["remove_manager"], self.local)
        self.assertEqual(outcome.report[1:5], [
            f"  from Homebrew 7.0.11 at {self.usr_local} (Apple Silicon): its packages are unknown",
            f"  from MacPorts 2.12.7 at {self.local} (Apple Silicon): 1 port",
            f"  then uninstalling MacPorts at {self.local}, which will be empty",
            f"  Homebrew at {self.usr_local} stays installed: its Cellar or Caskroom folder cannot be read, so "
            "brew-ports cannot tell that it will be empty"])


class KeptTest(PlannerCase):
    """The kept set: root-owned kegs, and the roots that kept packages need"""

    def test_root_owned_keg_keeps_the_formula(self):
        self.brew_source(formula("wget", self.usr_local), root_owned={"wget": [self.usr_local + "/opt/wget/x"]})
        self.ports_target()
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(names(outcome.plan.kept), ["wget"])
        self.assertEqual(outcome.plan.removal_set, {})
        self.assertEqual(outcome.plan.options["remove_manager"], "")
        self.assertEqual([m.target_name for m in outcome.plan.mappings], ["wget"])
        title = f"Staying in Homebrew at {self.usr_local}"
        self.assertEqual(self.section(outcome, title), [
            title, "  wget 1.0: some of its files belong to root, so `brew` cannot uninstall it; `brew-ports doctor` "
                   "says how to fix that"])

    def test_root_kept_by_a_kept_package_keeps_its_mapping(self):
        self.ports_source(port("vim", self.local, "9.1", deps=["wget"]), port("wget", self.local, "1.25.0"))
        self.brew_target()
        plan = self.plan(keep=["vim"]).plan
        self.assertEqual(names(plan.kept), ["vim", "wget"])
        self.assertEqual([m.target_name for m in plan.mappings], ["wget"])
        self.assertEqual(plan.removal_set, {})

    def test_dropped_root_a_kept_package_needs_stays(self):
        self.ports_source(port("vim", self.local, "9.1", deps=["libidn2"]), port("libidn2", self.local, "2.3"))
        self.brew_target()
        outcome = self.plan(keep=["vim"], drop=["libidn2"])
        self.assert_exit(outcome, 0)
        self.assertEqual(names(outcome.plan.kept), ["libidn2", "vim"])
        self.assertIn(f"  libidn2 (MacPorts at {self.local}) stays, although you asked to uninstall it: vim needs it",
                      outcome.report)
        # A package that stays is not one the plan uninstalls.
        self.assertNotIn("Uninstalled without a replacement", outcome.report)


class ServicesTest(PlannerCase):
    """The services phase 5 stops, and a user job that the plan breaks"""

    def setUp(self):
        super().setUp()
        self.brew_source(formula("wget", self.usr_local, executables=["wget"]))
        self.brew_target(formula("wget", self.path("opt", "homebrew")))
        home = "/Users/alice/Library/LaunchAgents/"
        self.world.services += [
            service("homebrew.mxcl.wget", home + "homebrew.mxcl.wget.plist", self.usr_local, package="wget"),
            service("homebrew.mxcl.wget", self.target.prefix + "/opt/wget/homebrew.mxcl.wget.plist",
                    self.target.prefix, package="wget"),
            service("com.alice.fetch", home + "com.alice.fetch.plist", self.usr_local, owned=False,
                    program=self.usr_local + "/bin/wget"),
        ]

    def test_only_the_source_service_is_listed(self):
        outcome = self.plan(start_services=True)
        title = "Services of the packages to uninstall"
        # Nothing runs, so nothing is stopped and no replacement is started, whatever the option asks for.
        self.assertEqual(self.section(outcome, title), [title, "  homebrew.mxcl.wget (wget): not running"])
        self.assertIn("  5  Uninstall the old packages", outcome.report)

    def test_a_running_service_is_stopped_and_started_on_request(self):
        self.world.services[0].loaded = True
        title = "Services of the packages to uninstall"
        running = "  homebrew.mxcl.wget (wget): running; it is stopped first"
        self.assertEqual(self.section(self.plan(), title), [
            title, running, "  Its replacement is not started: plan with --start-services to start it"])
        started = self.plan(start_services=True)
        self.assertEqual(self.section(started, title), [
            title, running, "  The replacement of the running one is started afterwards (--start-services)"])
        self.assertIn("  5  Uninstall the old packages, after stopping 1 service", started.report)
        self.world.services[0].scope = "system"
        self.assertEqual(self.section(self.plan(start_services=True), title)[-1],
                         "  A service that runs as root is not started in Homebrew: `apply` prints the command for you")

    def test_user_job_is_reported_not_acted_on(self):
        outcome = self.plan()
        plist = report.tilde("/Users/alice/Library/LaunchAgents/com.alice.fetch.plist")
        title = "To do before `brew-ports apply`"
        self.assertEqual(self.section(outcome, title), [
            title, f"  Your own service {plist} runs {self.usr_local}/bin/wget, which this plan uninstalls. Point it "
                   "at the replacement, or delete it. `apply` stops before it deletes the installation while the "
                   "service runs."])
        mentions = [(phase.number, action.kind) for phase in outcome.plan.phases for action in phase.actions
                    if "com.alice.fetch" in " ".join(action.argv) + action.description]
        self.assertEqual(mentions, [(6, "note")])


class LoginShellTest(PlannerCase):
    """A login shell the plan would remove: kept unless its mapping installs the same basename"""

    def setUp(self):
        super().setUp()
        self.brew_source(formula("bash", self.usr_local, version="5.3"))
        self.ports_target(add=[{"name": "bash", "version": "5.3.3"}, {"name": "zsh", "version": "5.9"}])
        self.world.environment = {"login_shell": self.usr_local + "/bin/bash",
                                  "login_shell_realpath": self.usr_local + "/Cellar/bash/5.3/bin/bash",
                                  "login_shell_prefix": self.usr_local}

    def test_same_basename_removes_the_package(self):
        plan = self.plan().plan
        self.assertEqual(plan.removal_set, {self.usr_local: [("formula", "bash")]})

    def test_other_basename_keeps_the_package(self):
        outcome = self.plan(maps=["bash=zsh"])
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual(plan.removal_set, {})
        self.assertEqual(names(plan.kept), ["bash"])
        self.assertEqual(plan.mappings, [])
        self.assertEqual(plan.unmigratable[0].evidence[0], (
            f"kept: it is your login shell ({self.usr_local}/bin/bash), and its replacement, zsh, is not known to "
            "provide `bash`; change your shell first (`chsh -s /bin/zsh`) to move it"))

    def test_a_shell_that_no_package_owns_keeps_its_installation(self):
        self.world.environment["login_shell"] = self.usr_local + "/bin/fish"
        self.world.environment["login_shell_realpath"] = self.usr_local + "/bin/fish"
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.options["remove_manager"], "")
        self.assertNotIn(6, [phase.number for phase in outcome.plan.phases])
        why = (f"your login shell ({self.usr_local}/bin/fish) is inside it and belongs to no package: change your "
               "shell first (`chsh -s /bin/zsh`), then plan again")
        self.assertIn(f"  Homebrew at {self.usr_local} stays installed, because {why}", outcome.report)
        refused = self.plan(delete=[self.usr_local])
        self.assert_exit(refused, 1)
        self.assertIn(f"    --delete {self.usr_local}: Homebrew at {self.usr_local} cannot be deleted while {why}",
                      refused.problems)

    def test_a_shell_whose_package_stays_is_left_alone(self):
        plan = self.plan(keep=["bash"]).plan
        self.assertEqual(plan.removal_set, {})
        self.assertEqual(names(plan.kept), ["bash"])


class LanguageTest(PlannerCase):
    """A language package root and its requirements file"""

    def test_language_port_gets_a_requirements_file(self):
        self.ports_source(port("py313-serial", self.local, "3.5", homepage="https://github.com/pyserial/pyserial"))
        self.brew_target()
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        mapping = outcome.plan.unmigratable[0]
        path = os.path.join(os.path.dirname(outcome.path), "language-pip.txt")
        self.assertEqual(mapping.evidence[0], "it is a Python package, which the plan does not move: "
                                              f"{report.tilde(path)} lists what to reinstall")
        title = "Python packages are not moved. The list to reinstall them from"
        self.assertEqual(self.section(outcome, title), [title, f"  {report.tilde(path)}"])
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(f"serial  # from py313-serial (MacPorts at {self.local})", text)
        self.assertIn("pipx install", text)
        self.assertEqual(names(outcome.plan.kept), ["py313-serial"])


class TwoSourcesTest(PlannerCase):
    """Two sources: each one the move empties is uninstalled, and one that keeps a package stays"""

    def test_only_the_emptied_one_of_two_sources_is_uninstalled(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        self.brew_source(formula("gnu-sed", self.usr_local, version="4.10"), formula("gnu-tar", self.usr_local))
        self.brew_target()
        plan = self.plan().plan
        self.assertEqual(plan.options["remove_manager"], f"{self.local},{self.usr_local}")
        self.assertEqual({a.instance_prefix for a in actions(plan, 6)}, {self.local, self.usr_local})
        plan = self.plan(keep=["gnu-tar"]).plan
        self.assertEqual(plan.options["remove_manager"], self.local)
        self.assertEqual({a.instance_prefix for a in actions(plan, 6)}, {self.local})
        self.assertEqual(sorted(plan.removal_set), sorted([self.local, self.usr_local]))


class HelpersTest(TempDirTest):
    """The helpers of `plan_sets`: extras ties, `package_at`, colliding files and the login shell's basename"""

    def test_extras_belong_to_their_interpreter(self):
        brew = instance(BREW, self.path("usr", "local"))
        ports = instance(PORTS, self.path("opt", "local"))
        units = {brew.prefix: plan_sets.units_of(brew, [formula(n, brew.prefix) for n in
                                                        ("python@3.13", "node@22", "ruby", "perl", "wget")]),
                 ports.prefix: plan_sets.units_of(ports, [port(n, ports.prefix) for n in
                                                          ("python313", "nodejs22", "ruby34", "perl5.40")])}
        extras = {"python": [{"version": "3.13", "instance_prefix": None, "location": "user",
                              "instances": [brew.prefix, ports.prefix], "dists": [{"name": "rich"}]}],
                  "pipx": [{"name": "black", "home": brew.prefix + "/opt/python@3.13/bin",
                            "instance_prefix": brew.prefix}],
                  "npm": [{"instance_prefix": brew.prefix, "name": "yarn"}, {"instance_prefix": ports.prefix,
                                                                            "name": "pnpm"}],
                  "gems": [{"instance_prefix": ports.prefix, "name": "rails"}],
                  "cpan": [{"instance_prefix": brew.prefix, "module": "Foo::Bar"}]}
        ties = plan_sets.extras_ties(extras, units)
        owners = sorted((k[0] == brew.prefix, k[2]) for k in ties)
        self.assertEqual(owners, [(False, "nodejs22"), (False, "python313"), (False, "ruby34"),
                                  (True, "node@22"), (True, "perl"), (True, "python@3.13")])
        self.assertIn("the pipx tool black", ties[(brew.prefix, "formula", "python@3.13")])

    def test_package_at_reads_cellar_then_executables(self):
        brew = instance(BREW, self.path("usr", "local"))
        units = plan_sets.units_of(brew, [formula("bash", brew.prefix, executables=["bash"]),
                                          formula("zsh", brew.prefix, executables=["zsh"])])
        graph = plan_sets.SourceGraph(brew, units, lambda name, kind: None)
        found = plan_sets.package_at(graph, brew.prefix + "/bin/fish", brew.prefix + "/Cellar/zsh/5.9/bin/fish")
        self.assertEqual(found.name, "zsh")
        self.assertEqual(plan_sets.package_at(graph, brew.prefix + "/bin/bash", brew.prefix + "/bin/bash").name,
                         "bash")
        self.assertIsNone(plan_sets.package_at(graph, brew.prefix + "/bin/tcsh", brew.prefix + "/bin/tcsh"))

    def test_colliding_files(self):
        src = instance(PORTS, self.path("opt", "local2"), applications_dir="/Applications/MacPorts")
        dst = instance(PORTS, self.path("opt", "local"), applications_dir="/Applications/MacPorts")
        files = [src.prefix + "/bin/x", "/Library/LaunchDaemons/org.macports.x.plist", "/Applications/MacPorts/X.app"]
        self.assertEqual(plan_sets.colliding_files(src, dst, files), files[1:])
        dst.applications_dir = "/Applications/Other"
        self.assertEqual(plan_sets.colliding_files(src, dst, files), files[1:2])

    def test_installs_basename(self):
        mapping = model.Mapping(source=formula("bash", "/x"), target_kind="formula", target_name="bash@5",
                                target_version=None, confidence=model.Confidence.EXACT, evidence=[], companions=[],
                                selections=[], variants_note=None)
        self.assertTrue(plan_sets.installs_basename(mapping, "bash", BREW, lambda name: ["bash", "bashbug"]))
        self.assertFalse(plan_sets.installs_basename(mapping, "bash", BREW, lambda name: ["sh"]))
        self.assertFalse(plan_sets.installs_basename(mapping, "bash", PORTS, lambda name: []))
        self.assertFalse(plan_sets.installs_basename(None, "bash", BREW, lambda name: ["bash"]))


class OutsideFilesTest(PlannerCase):
    """Files outside the prefix in a migration from one MacPorts prefix to another"""

    def setUp(self):
        super().setUp()
        self.src = self.path("opt", "local2")
        self.world.files[self.src] = {
            ("dbus", "@1.16.2_0"): [(self.src + "/bin/dbus-daemon", True),
                                    ("/Library/LaunchDaemons/org.freedesktop.dbus-system.plist", True)],
            ("frotz", "@2.54_0"): [(self.src + "/bin/frotz", True), ("/Applications/MacPorts/Frotz.app", True)],
            ("wget", "@1.25.0_0"): [(self.src + "/bin/wget", True)],
        }
        self.ports_source(port("dbus", self.src, "1.16.2"), port("frotz", self.src, "2.54"),
                          port("wget", self.src, "1.25.0"), prefix=self.src)

    def target_with(self, apps):
        """Add the MacPorts target, its PortIndex listing dbus and frotz

        @param apps  the target's `applications_dir`
        """
        self.ports_target(add=[{"name": "dbus", "version": "1.16.2"}, {"name": "frotz", "version": "2.54"}],
                          applications_dir=apps)

    def test_startup_item_and_shared_apps_dir_keep_ports(self):
        self.target_with("/Applications/MacPorts")
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual(names(plan.kept), ["dbus", "frotz"])
        self.assertEqual(plan.removal_set, {self.src: [("port", "wget")]})
        reasons = {m.source.name: m.evidence[0] for m in plan.unmigratable}
        self.assertIn("/Library/LaunchDaemons/org.freedesktop.dbus-system.plist", reasons["dbus"])
        self.assertEqual(reasons["frotz"], f"kept: its replacement in MacPorts at {self.local} would overwrite its "
                                           f"files outside {self.src} (/Applications/MacPorts/Frotz.app)")
        self.assertEqual([a.action_id for a in actions(plan, 3)], ["3.install.wget"])

    def test_own_apps_dir_bundles_do_not_collide(self):
        self.target_with("/Applications/MacPorts-new")
        plan = self.plan().plan
        self.assertEqual(names(plan.kept), ["dbus"])
        self.assertIn(("port", "frotz"), plan.removal_set[self.src])


if __name__ == "__main__":
    unittest.main()

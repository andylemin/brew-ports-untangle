"""The kept and removal sets: casks, `--only`, undrivable sources, the login shell, files outside a prefix"""

import os
import unittest

from brew_ports import model, plan_sets
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
        self.assertIn("needed by wget", self.text(outcome))

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
        self.assertIn("inactive in the source", self.text(outcome))
        self.assertEqual(outcome.plan.removal_set, {self.local: [("port", "wget")]})
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
        self.assertIn(f"port gsed ({self.local}) is needed by port wget (outside --only): name it in --only too, "
                      "or leave gsed out", self.text(outcome))

    def test_only_sweeps_unneeded_dependencies(self):
        self.world.packages = [p for p in self.world.packages if p.name != "other"]
        outcome = self.plan(only=["wget"])
        self.assert_exit(outcome, 0)
        self.assertEqual(outcome.plan.removal_set, {self.local: [("port", "libidn2"), ("port", "wget")]})
        text = self.text(outcome)
        self.assertIn(f"left installed: port gsed ({self.local}): installed on request", text)
        self.assertIn(f"left installed: port libsvc ({self.local}): owns the service org.macports.libsvc", text)
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
    """Casks under a MacPorts target: `--casks keep|drop|map`, manual casks, data casks"""

    def test_a_cask_depending_on_a_formula(self):
        self.brew_source(cask("vlc", self.usr_local, deps=["libfoo"]), formula("libfoo", self.usr_local,
                                                                            requested=False))
        self.ports_target()
        dropped = self.plan(casks="drop")
        self.assert_exit(dropped, 0)
        self.assertEqual(dropped.plan.removal_set, {self.usr_local: [("cask", "vlc"), ("formula", "libfoo")]})
        self.assertEqual(dropped.plan.roots, [])
        self.assertIn(f"vlc ({self.usr_local}): reinstall by hand from", self.text(dropped))
        kept = self.plan()
        self.assert_exit(kept, 0)
        self.assertEqual(kept.plan.removal_set, {})
        self.assertEqual(names(kept.plan.kept), ["libfoo", "vlc"])
        self.assertIn("retained for the cask vlc", self.text(kept))

    def test_kept_cask_needing_a_removed_cask_exits_1(self):
        self.brew_source(cask("miniconda", self.usr_local, caskroom_data=[CONDA]),
                         cask("kept-app", self.usr_local, cask_deps=["miniconda"]))
        self.ports_target()
        outcome = self.plan(drop=["miniconda"])
        self.assert_exit(outcome, 1)
        self.assertIn(f"cask miniconda ({self.usr_local}) is needed by cask kept-app (kept: --casks keep)",
                      self.text(outcome))

    def test_manual_cask_needing_a_removed_cask_exits_1(self):
        self.brew_source(cask("helper", self.usr_local),
                         cask("rooted", self.usr_local, cask_deps=["helper"], privileged_uninstall=True))
        self.ports_target()
        outcome = self.plan(casks="drop")
        self.assert_exit(outcome, 1)
        self.assertIn(f"cask helper ({self.usr_local}) is needed by cask rooted (a manual cask)", self.text(outcome))

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

    def test_privileged_cask_is_a_manual_cask(self):
        self.privileged_source()
        outcome = self.plan(casks="drop")
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual(plan.manual_casks, ["rooted"])
        self.assertEqual(plan.removal_set, {self.usr_local: [("formula", "wget")]})
        self.assertEqual(names(plan.kept), ["libfoo"])
        self.assertIn(f"{self.usr_local}/bin/brew uninstall --cask rooted", self.text(outcome))

    def test_manual_cask_refuses_remove_manager(self):
        self.privileged_source()
        refused = self.plan(casks="drop", remove_manager=[self.usr_local])
        self.assert_exit(refused, 1)
        self.assertIn("it keeps packages: libfoo", self.text(refused))
        self.assertIn("it has manual casks", self.text(refused))

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
        self.assertIn("--casks map found no accepted mapping", self.text(outcome))

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
            self.assertIn(f"keeps data in {CONDA}", [m.evidence[0] for m in plan.unmigratable], policy)
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
        self.assertEqual(reasons["miniconda"], f"keeps data in {CONDA}")
        self.assertTrue(reasons["1kc-razer"].startswith("Homebrew refuses to install 1kc-razer"))
        self.assertTrue(reasons["virtualbox"].startswith("cask needs sudo to install"))
        self.assertEqual(names(plan.kept), ["1kc-razer", "miniconda", "virtualbox"])
        self.assertEqual([a.action_id for a in actions(plan, 3)], ["3.adopt.firefox"])

    def test_dropped_sudo_cask_is_a_manual_cask(self):
        ask = FakeAsk({"virtualbox": "drop", "1kc-razer": "drop"})
        plan = self.plan(ask=ask).plan
        self.assertEqual(plan.manual_casks, ["virtualbox"])
        self.assertEqual(plan.removal_set, {self.usr_local: [("cask-adopted", "firefox"), ("cask", "1kc-razer")]})
        self.assertEqual(names(plan.kept), ["miniconda"])
        self.assertFalse(any("miniconda" in q for q in ask.asked))


class UndrivableTest(PlannerCase):
    """An undrivable source: refused, deleted by path, or left in place under `--only`"""

    def setUp(self):
        super().setUp()
        self.brew_source(formula("wget", self.usr_local), cask("firefox", self.usr_local),
                         drivable=False, usability=Usability.CANNOT_RUN)
        self.brew_target()

    def test_full_migration_exits_1(self):
        outcome = self.plan()
        self.assert_exit(outcome, 1)
        draft = outcome.draft
        self.assertEqual(names(draft.left_in_place), ["firefox", "wget"])
        self.assertEqual(draft.removal_set, {})
        self.assertEqual(sorted(m.source.name for m in draft.mappings), ["firefox", "wget"])
        self.assertIn("cannot be driven (cannot-run), so it uninstalls nothing", self.text(outcome))

    def test_remove_manager_deletes_it_by_path(self):
        outcome = self.plan(remove_manager=[self.usr_local])
        self.assert_exit(outcome, 0)
        plan = outcome.plan
        self.assertEqual(plan.path_removed, {self.usr_local: [("cask-adopted", "firefox"), ("formula", "wget")]})
        self.assertEqual(plan.removal_set, {})
        self.assertEqual(plan.left_in_place, [])
        self.assertIn(6, [p.number for p in plan.phases])
        self.assertEqual({a.action_id for a in actions(plan, 3)}, {"3.install.bottled", "3.adopt.firefox"})

    def test_under_only_it_stays_in_place(self):
        outcome = self.plan(only=["wget"])
        self.assert_exit(outcome, 0)
        self.assertEqual(names(outcome.plan.left_in_place), ["firefox", "wget"])
        self.assertEqual([m.target_name for m in outcome.plan.mappings], ["wget"])

    def test_unknown_inventory_refuses_a_full_migration(self):
        self.world.instances[0].inventory_known = False
        self.world.packages = []
        outcome = self.plan()
        self.assert_exit(outcome, 1)
        self.assertIn("its packages are unknown (ports-damaged-registry)", self.text(outcome))


class KeptTest(PlannerCase):
    """The kept set: root-owned kegs, and the roots that kept packages need"""

    def test_root_owned_keg_keeps_the_formula(self):
        self.brew_source(formula("wget", self.usr_local), root_owned={"wget": [self.usr_local + "/opt/wget/x"]})
        self.ports_target()
        outcome = self.plan()
        self.assert_exit(outcome, 0)
        self.assertEqual(names(outcome.plan.kept), ["wget"])
        self.assertEqual(outcome.plan.removal_set, {})
        self.assertEqual([m.target_name for m in outcome.plan.mappings], ["wget"])
        self.assertIn("root-owned keg paths (brew-root-owned-keg)", self.text(outcome))

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
        self.assertIn("stays although dropped: needed by vim", self.text(outcome))


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

    def test_only_the_source_service_is_stopped(self):
        outcome = self.plan()
        text = self.text(outcome)
        self.assertIn(f"homebrew.mxcl.wget ({self.usr_local}, formula wget)", text)
        self.assertNotIn(f"homebrew.mxcl.wget ({self.target.prefix}", text)

    def test_user_job_is_reported_not_acted_on(self):
        outcome = self.plan()
        self.assertIn("will stop working: /Users/alice/Library/LaunchAgents/com.alice.fetch.plist runs "
                      f"{self.usr_local}/bin/wget", self.text(outcome))
        for phase in outcome.plan.phases:
            for action in phase.actions:
                self.assertNotIn("com.alice.fetch", " ".join(action.argv) + action.description)


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
        self.assertEqual(plan.unmigratable[0].evidence[0], f"kept: provides the login shell {self.usr_local}/bin/bash")

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
        self.assertEqual(mapping.evidence[0], f"language package: see {path}")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(f"serial  # from port py313-serial ({self.local})", text)
        self.assertIn("pipx install", text)
        self.assertEqual(names(outcome.plan.kept), ["py313-serial"])


class TwoSourcesTest(PlannerCase):
    """`--remove-old` naming one of two sources"""

    def test_remove_manager_names_one_of_two_sources(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        self.brew_source(formula("gnu-sed", self.usr_local, version="4.10"))
        self.brew_target()
        plan = self.plan(remove_manager=[self.local]).plan
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
        self.assertIn("the pipx venv black", ties[(brew.prefix, "formula", "python@3.13")])

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
        self.assertTrue(reasons["frotz"].startswith("kept: its files outside the prefix collide"))
        self.assertEqual([a.action_id for a in actions(plan, 3)], ["3.install.wget"])

    def test_own_apps_dir_bundles_do_not_collide(self):
        self.target_with("/Applications/MacPorts-new")
        plan = self.plan().plan
        self.assertEqual(names(plan.kept), ["dbus"])
        self.assertIn(("port", "frotz"), plan.removal_set[self.src])


if __name__ == "__main__":
    unittest.main()

"""What the plan fixes ahead of the run: upgrades, repairs, installs, rebuilds and the phase 6 previews"""

import os
import unittest
from unittest import mock

from brew_ports import doctor, plan_phases
from brew_ports.homebrew import actions as brew_actions
from brew_ports.model import Confidence, Mapping, OnFailure, Severity
from tests.unit.fixtures.doctor.builders import service
from tests.unit.fixtures.planner.builders import PlannerCase, actions, cask, formula, port

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
        self.assertIn("3.5.0 -> 3.6.0", text)
        self.assertIn("a dependency of wget", text)
        self.assertIn("depends on openssl@3", text)
        # Only mapped targets and companions are upgraded by name; build-only dependencies are no upgrades.
        self.assertNotIn("3.upgrade.formulae", ids(plan, 3))
        self.assertNotIn("pkgconf", plan.target_upgrades)

    def test_a_pinned_install_blocker_exits_1(self):
        self.make_target(pinned=True)
        outcome = self.plan()
        self.assert_exit(outcome, 1)
        self.assertIn("the pinned openssl@3 would be upgraded (a dependency of wget), which the mappings of wget need: "
                      "run `brew unpin openssl@3`", self.text(outcome))
        self.assertEqual(outcome.draft.target_upgrades, ["openssl@3", "curl"])

    def test_keeping_the_root_clears_the_blocker(self):
        self.make_target(pinned=True)
        self.assert_exit(self.plan(keep=["wget"]), 0)


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
            self.assertEqual(action.env_profile, "brew")
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
        self.assertIn(f"remaining cross-prefix link: {binary} -> {lib} (other)", self.text(kept))

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
    """The phase 6 previews of the instances `--remove-manager` names"""

    def test_previews_of_a_named_macports_instance(self):
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
        plan = self.plan(remove_manager=[src]).plan
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
        acts = actions(self.plan(remove_manager=[]).plan, 6)
        self.assertFalse([a for a in acts if a.action_id.startswith("6.delete.")])
        self.assertTrue(any("holds no etc/macports/macports.conf" in a.description for a in acts))

    def test_previews_of_a_named_homebrew_instance(self):
        prefix = self.usr_local
        for sub in ("Cellar/wget/1.25.0", "Homebrew/Library/Taps/homebrew", "var/homebrew/linked", "etc", "bin"):
            os.makedirs(os.path.join(prefix, sub), exist_ok=True)
        with open(os.path.join(prefix, "bin", "brew"), "w"):
            pass
        self.brew_source(formula("wget", prefix, version="1.25.0"), repository=prefix + "/Homebrew")
        self.brew_target()
        with mock.patch("brew_ports.homebrew.locate.USR_LOCAL", prefix):
            acts = actions(self.plan(remove_manager=[prefix]).plan, 6)
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
            outcome = self.plan(remove_manager=[prefix], casks="drop", environ={"HOME": home})
        self.assert_exit(outcome, 0)
        acts = actions(outcome.plan, 6)
        tag = prefix.replace("/", "%")
        notes = {a.action_id: a.description for a in acts if a.kind == "note"}
        self.assertEqual(notes[f"6.note.{tag}.remaining"], (
            f"then, after a second confirmation that --yes answers, every entry left in {prefix} is archived into "
            f"<run>/data-archive/ unless an archive above holds it, and deleted; a no keeps {prefix} with them; "
            "besides the paths above it holds bin, etc, var at plan time"))
        self.assertEqual(notes[f"6.note.{tag}.prefix"], f"then {prefix} itself (rm -d), once nothing is left in it")
        self.assertEqual((acts[-1].action_id, acts[-1].description), (
            f"6.note.{tag}.caches", "last, once no Homebrew instance survives the phase, the caches and logs every "
            f"Homebrew instance shares are deleted without an archive: {', '.join(caches)}"))

    def test_phase_6_only_when_an_instance_goes(self):
        self.ports_source(port("wget", self.local, "1.25.0"))
        self.brew_target()
        self.assertEqual([p.number for p in self.plan().plan.phases], [0, 1, 2, 3, 4, 5, 7, 8])
        phases = self.plan(remove_manager=[]).plan.phases
        self.assertEqual([p.number for p in phases], [0, 1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual([p.number for p in phases if p.confirm], [1, 2, 3, 5, 6, 7])
        self.assertEqual([p.actions for p in phases if p.number in (0, 1, 4, 5, 7, 8)], [[]] * 6)


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

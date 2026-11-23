"""Phases 2 and 3 of `apply`: repairs, resumed installs and adoptions, and rebuilds of target packages"""

import dataclasses
import os
import types
import unittest
from unittest import mock

from brew_ports import doctor, exec_install, executor, runner, state
from brew_ports.homebrew import actions as brew_actions
from brew_ports.model import OnFailure
from tests.unit.fixtures.executor import builders as b
from tests.unit.helpers import TempDirTest, make_instance, make_package
from tests.unit.test_executor import ApplyTest


class RepairTest(ApplyTest):
    """Phase 2: the post-check of each finding decides its result lines"""

    def setUp(self):
        super().setUp()
        target = b.brew_prefix(self.tmp, "opt/homebrew")
        b.keg(target, "wget", "1.24.5", requested=None)
        self.target = b.brew(target)
        self.host.instances = [self.target]
        self.host.environment = {"files": [], "etc_paths": []}
        wget = f"2.brew-keg-without-receipt.{state.slug(os.path.join(target, 'Cellar', 'wget'))}"
        jq = f"2.brew-missing-dependency.{state.slug(os.path.join(target, 'Cellar', 'jq'))}"
        self.receipt = [
            dataclasses.replace(brew_actions.reinstall(self.target, "arm64", wget + ".reinstall", ["wget"]),
                                description="brew-keg-without-receipt wget: reinstall formulae"),
            dataclasses.replace(brew_actions.tab_installed_on_request(self.target, "arm64", wget + ".tab", ["wget"]),
                                description="brew-keg-without-receipt wget: mark as installed on request")]
        self.dependency = dataclasses.replace(
            brew_actions.install_formulae(self.target, "arm64", jq + ".install", ["oniguruma"]),
            description="brew-missing-dependency jq: install formulae")
        self.save_plan(b.plan(self.target, [], phase2=self.receipt + [self.dependency]))
        self.checked = []
        self.verdicts = {"brew-keg-without-receipt": False}

    def verify(self, issue, _runner, _bundle):
        """Stand in for `doctor.verify`: record the finding, then answer from `verdicts`

        @param issue    the finding to check
        @param _runner  the run's runner
        @param _bundle  the run's scan
        @returns        the verdict; None leaves the decision to the exit statuses
        """
        self.checked.append((issue.code, issue.subject, issue.instance_prefix, [a.action_id for a in issue.remedies]))
        return self.verdicts.get(issue.code)

    def apply_phase_2(self, **kw):
        """Run `apply` up to phase 2, which must exit 0, with `verify` as the post-check

        @param kw  further command line values, such as `resume`
        """
        with mock.patch("brew_ports.doctor.verify", side_effect=self.verify):
            self.assertEqual(self.apply(stop_after=2, **kw), executor.EXIT_OK, self.out)

    def test_post_check_decides_the_result_lines(self):
        self.apply_phase_2()
        results = self.results()
        self.assertEqual([results[(2, a.action_id)] for a in self.receipt], ["failed", "failed"])
        self.assertEqual(results[(2, self.dependency.action_id)], "ok")
        self.assertIn("  wget is not repaired (the problem is still there). Phase 4 checks whether that matters.\n",
                      self.out)
        self.assertNotIn("jq is not repaired", self.out)
        for action in self.receipt + [self.dependency]:
            self.assertIn(f"  {doctor.describe(action)} ... ok\n", self.out)
        self.assertEqual(self.checked[0][:3], ("brew-keg-without-receipt", "wget", self.target.prefix))
        self.assertEqual(self.checked[0][3], [a.action_id for a in self.receipt])

    def test_resume_reruns_only_the_failed_finding(self):
        self.apply_phase_2()
        self.verdicts["brew-keg-without-receipt"] = True
        self.responder.log.clear()
        self.apply_phase_2(resume=self.run_dir.run_id)
        verbs = [tail[1] for tail in self.responder.ran("brew") if tail[1] in ("reinstall", "tab", "install")]
        self.assertEqual(verbs, ["reinstall", "tab"])
        self.assertEqual(self.results()[(2, self.receipt[1].action_id)], "ok")

    def test_stop_failure_ends_only_its_finding(self):
        self.responder.fail = {"wget": 1}
        self.apply_phase_2()
        results = self.results()
        self.assertEqual(results[(2, self.receipt[0].action_id)], "failed")
        self.assertNotIn((2, self.receipt[1].action_id), results)
        self.assertEqual(results[(2, self.dependency.action_id)], "ok")
        self.assertEqual([c[0] for c in self.checked], ["brew-missing-dependency"])


class FindingTest(unittest.TestCase):
    """The phase 2 actions grouped by finding, and the finding each group rebuilds"""

    def setUp(self):
        receipt = f"2.brew-keg-without-receipt.{state.slug('/opt/homebrew/Cellar/python@3.12')}"
        self.group = [self.action(receipt + ".reinstall", "brew-keg-without-receipt python@3.12: reinstall formulae"),
                      self.action(receipt + ".tab", "brew-keg-without-receipt python@3.12: mark")]
        self.other = self.action("2.ports-missing-image.%opt%local.%opt%local%jq.rebuild",
                                 "ports-missing-image jq: rebuild jq", "/opt/local")

    @staticmethod
    def action(action_id, description, prefix="/opt/homebrew"):
        """Return a stand-in for a phase 2 action: its id, description and prefix

        @param action_id    the action's id
        @param description  its description, which names the finding's subject
        @param prefix       its instance's prefix
        @returns            the stand-in
        """
        return types.SimpleNamespace(action_id=action_id, description=description, instance_prefix=prefix)

    def test_findings_groups_actions_by_finding(self):
        groups = exec_install.findings(self.group + [self.other])
        self.assertEqual([[a.action_id for a in g] for g in groups],
                         [[a.action_id for a in self.group], [self.other.action_id]])

    def test_finding_reads_its_code_and_subject(self):
        issue = exec_install.finding(self.group)
        self.assertEqual((issue.code, issue.subject, issue.instance_prefix),
                         ("brew-keg-without-receipt", "python@3.12", "/opt/homebrew"))
        self.assertEqual(exec_install.finding([self.other]).subject, "jq")

    def test_a_rebuild_keeps_homebrew_to_the_one_formula(self):
        run = types.SimpleNamespace(runner=types.SimpleNamespace(host_arch="arm64"), homebrew_present=True)
        again = exec_install.rebuild_action(run, make_instance(prefix="/opt/homebrew", arch="arm64"), "curl", [])
        self.assertEqual(again.argv[-3:], ["reinstall", "--formula", "curl"])
        # Homebrew must not go on to upgrade what uses curl: the plan lists every upgrade of the move.
        self.assertEqual(again.env_profile, runner.BREW_NAMED_ONLY)


class ReinstallSplitTest(TempDirTest):
    """What an interrupted batch install poured, against the listing journaled before it"""

    def run_stub(self, catalogue, actions=()):
        """Return a stand-in for a run: a scan with one catalogue, and the actions of every phase

        @param catalogue  the catalogue the scan holds
        @param actions    the actions `run.actions` returns
        @returns          the stand-in
        """
        return types.SimpleNamespace(bundle=types.SimpleNamespace(catalogue=lambda prefix: catalogue),
                                     actions=lambda number: list(actions))

    def test_formulae_named_and_poured(self):
        prefix = b.brew_prefix(self.tmp, "opt/homebrew")
        target = b.brew(prefix)
        before = {"cellar": {"openssl@3": ["3.4.0"]}, "caskroom": {}}
        for name, version in (("openssl@3", "3.4.0"), ("jq", "1.7.1"), ("oniguruma", "6.9.9")):
            b.keg(prefix, name, version)
        action = b.install_action(target, "3.install.bottled", ["dnsmasq", "jq"])
        catalogue = b.FakeCatalogue(versions={"jq": "1.7.1", "dnsmasq": "2.90", "oniguruma": "6.9.9"})
        formulae, tokens, rest = exec_install.reinstall_split(self.run_stub(catalogue), target, action, before)
        self.assertEqual((formulae, tokens, rest), (["jq", "oniguruma"], [], ["dnsmasq"]))

    def test_unpoured_upgrade_reruns_as_upgrade(self):
        prefix = b.brew_prefix(self.tmp, "opt/homebrew")
        target = b.brew(prefix)
        b.keg(prefix, "openssl@3", "3.4.0")
        action = brew_actions.upgrade_formulae(target, "arm64", "3.upgrade.formulae", ["openssl@3"])
        catalogue = b.FakeCatalogue(versions={"openssl@3": "3.5.0"})
        before = {"cellar": {"openssl@3": ["3.4.0"]}, "caskroom": {}}
        self.assertEqual(exec_install.reinstall_split(self.run_stub(catalogue), target, action, before),
                         ([], [], ["openssl@3"]))
        b.keg(prefix, "openssl@3", "3.5.0")
        self.assertEqual(exec_install.reinstall_split(self.run_stub(catalogue), target, action, before),
                         (["openssl@3"], [], []))
        upgrade = exec_install._rest_action(target, "arm64", action, ["openssl@3"])
        self.assertEqual(upgrade.argv[-3:], ["upgrade", "--formula", "openssl@3"])

    def test_casks_never_reinstall_an_adopted_token(self):
        prefix = b.brew_prefix(self.tmp, "opt/homebrew")
        target = b.brew(prefix)
        for token in ("iterm2", "firefox", "zoom"):
            b.caskroom(prefix, token)
        b.keg(prefix, "lz4", "1.10.0")
        action = brew_actions.install_casks(target, "arm64", "3.install.casks", ["iterm2", "slack"])
        adopt = brew_actions.adopt_cask(target, "arm64", "3.adopt.firefox", "firefox")
        catalogue = b.FakeCatalogue(versions={"iterm2": "3.5", "slack": "4.0"})
        split = exec_install.reinstall_split(self.run_stub(catalogue, [adopt]), target, action,
                                             {"cellar": {}, "caskroom": {}})
        self.assertEqual(split, (["lz4"], ["iterm2", "zoom"], ["slack"]))


class AdoptionTest(ApplyTest):
    """A cask adoption that a Ctrl-C stopped"""

    def test_interrupted_adoption_reruns_as_adoption(self):
        target = b.brew_prefix(self.tmp, "opt/homebrew")
        source = b.brew_prefix(self.tmp, "usr/local")
        b.caskroom(source, "firefox", "130.0")
        self.target, self.source = b.brew(target), b.brew(source)
        firefox = make_package("firefox", "cask", source)
        self.host.instances = [self.target, self.source]
        self.host.packages = [firefox]
        self.host.environment = {"files": [], "etc_paths": []}
        adopt = brew_actions.adopt_cask(self.target, "arm64", "3.adopt.firefox", "firefox")
        self.save_plan(b.plan(self.target, [self.source],
                              mappings=[b.mapping(firefox, "cask", "firefox", version="130.0", adopt=True)],
                              removal={source: [("cask-adopted", "firefox")]}, phase3=[adopt]))

        def killed(tail):
            if "--adopt" in tail:
                self.runners[-1].note_sigint()
                return b.runner_mod.FakeResponse(exit=1)
            return None
        self.responder.hooks["install"] = killed
        self.assertEqual(self.apply(), executor.EXIT_ACTION, self.out)
        first = self.run_dir.run_id
        del self.responder.hooks["install"]
        self.responder.log.clear()
        self.assertEqual(self.apply(resume=first), executor.EXIT_OK, self.out)
        casks = [tail[1:] for tail in self.responder.ran("brew") if "--cask" in tail]
        self.assertEqual(casks, [["install", "--cask", "--adopt", "firefox"]])
        self.assertFalse(os.path.exists(os.path.join(source, "Caskroom", "firefox")))
        self.assertTrue(os.path.isdir(os.path.join(target, "Caskroom", "firefox")))


class RebuildTest(ApplyTest):
    """The rebuilds of the target packages that depend on a `target_upgrades` package"""

    def setUp(self):
        super().setUp()
        target = b.brew_prefix(self.tmp, "opt/homebrew")
        b.keg(target, "openssl@3", "3.5.0")
        self.curl = b.keg(target, "curl", "8.11.0", deps=["openssl@3"], exes=["curl"])
        self.wget = b.keg(target, "wget", "1.24.5", deps=["openssl@3"], exes=["wget"])
        b.keg(target, "tree", "2.2.1", exes=["tree"])
        self.target = b.brew(target)
        self.host.instances = [self.target]
        self.host.environment = {"files": [], "etc_paths": []}
        gone = os.path.join(target, "opt", "openssl@3", "lib", "libssl.3.dylib")
        self.responder.refs = {os.path.join(self.curl, "bin", "curl"): [gone],
                               os.path.join(self.wget, "bin", "wget"): [gone]}
        self.responder.refs_after = {"curl": []}
        self.responder.versions = {"curl": "8.11.0", "wget": "1.24.5", "tree": "2.2.1"}
        self.save_plan(b.plan(self.target, [], upgrades=["openssl@3"]))

    def reinstalls(self):
        """Return the formulae of each `brew reinstall` the run ran

        @returns  one list of names per reinstall, in run order
        """
        return [tail[3:] for tail in self.responder.ran("brew", "reinstall")]

    def test_broken_dependents_are_rebuilt(self):
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK, self.out)
        self.assertEqual(self.reinstalls(), [["curl"], ["wget"]])
        results = self.results()
        self.assertEqual((results[(3, "3.curl.rebuild")], results[(3, "3.wget.rebuild")]), ("ok", "failed"))
        brew = self.target.binary
        self.assertIn("  2 packages lost a library to an upgrade and will be installed again: curl, wget\n"
                      f"  {brew} reinstall --formula curl ... ok\n"
                      f"  {brew} reinstall --formula wget ... done, but wget still does not find a library it needs\n",
                      self.out)

    def test_rebuild_ids_survive_a_shorter_rescan(self):
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK, self.out)
        first = self.run_dir.run_id
        self.responder.log.clear()
        self.assertEqual(self.apply(resume=first, stop_after=3), executor.EXIT_OK, self.out)
        self.assertEqual(self.reinstalls(), [["wget"]])
        self.assertIn("  1 package lost a library to an upgrade and will be installed again: wget\n", self.out)

    def test_a_plan_rebuild_is_decided_by_its_rescan(self):
        rebuild = brew_actions.reinstall(self.target, "arm64", "3.tree.rebuild", ["tree"], on_failure=OnFailure.PROBE)
        other = os.path.join(self.tmp, "opt", "local")
        os.makedirs(os.path.join(other, "lib"))
        with open(os.path.join(other, "lib", "libz.1.dylib"), "w"):
            pass
        self.host.instances = [self.target, b.ports(other)]
        self.responder.refs[os.path.join(self.target.prefix, "Cellar", "tree", "2.2.1", "bin", "tree")] = [
            os.path.join(other, "lib", "libz.1.dylib")]
        self.save_plan(b.plan(self.target, [], phase3=[rebuild]))
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK, self.out)
        self.assertEqual(self.results()[(3, "3.tree.rebuild")], "failed")
        self.assertIn(f"  {self.target.binary} reinstall --formula tree ... done, but tree still does not find a "
                      "library it needs\n", self.out)


if __name__ == "__main__":
    unittest.main()

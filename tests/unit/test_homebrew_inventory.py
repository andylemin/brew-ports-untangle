"""The Homebrew inventory: the disk walk, the `brew` probes, the privileged flags, the degraded walk and the scan"""

import os
import unittest
from unittest import mock

from brew_ports import model, runner as r
from brew_ports.env import services
from brew_ports.homebrew import catalogue as cat, inventory as inv_mod, locate
from tests.unit.helpers import TempDirTest
from tests.unit.test_homebrew_support import (HomebrewTree, fake, fixture_catalogue, install_api, make_keg, receipt,
                                              root_owned_lstat, write)

BREW = ("/usr/bin/arch", "-arm64", "<tmp>/opt/homebrew/bin/brew")
GIT = ("/usr/bin/git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C")
TAPS = "<tmp>/opt/homebrew/Library/Taps"
OUTDATED = ('{"formulae": [{"name": "wget", "installed_versions": ["1.25.0_2"], "current_version": "1.25.0_3",'
            ' "pinned": true, "pinned_version": "1.25.0_2"}], "casks": []}')
DEPS = "jq: oniguruma\noniguruma: \nwget: libidn2 openssl@3\nalice/casks/sshfs-helper: libfido2\n"


class InventoryCase(TempDirTest):
    """A Homebrew tree in the temporary directory, with its fixture catalogue and the probes' canned answers"""

    def setUp(self):
        super().setUp()
        for target, name, value in ((locate, "SYSTEM_BREW_ENV", self.path("etc", "homebrew", "brew.env")),
                                    (cat, "LAUNCH_DAEMONS", self.path("LaunchDaemons"))):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.tree = HomebrewTree(self.tmp).build()
        self.catalogue = fixture_catalogue(prefix=self.tree.prefix, appdir=self.tree.appdir, home=self.tree.home)
        self.runner = fake(self.tmp)            # replaced by the runner of each run_inventory()

    def responses(self):
        """Return the canned answers of the inventory probes and of the two taps' `git status`

        @returns  the responses by argv, the temporary root spelled `<tmp>`
        """
        responses = {
            BREW + ("info", "--json=v2", "--installed"): r.FakeResponse(stdout=self.tree.info_json()),
            BREW + ("outdated", "--json=v2"): r.FakeResponse(stdout=OUTDATED),
            BREW + ("deps", "--formula", "--installed", "--for-each"): r.FakeResponse(stdout=DEPS),
            BREW + ("missing",): r.FakeResponse(exit=1, stdout="wget: libidn2\n"),
            GIT + (TAPS + "/homebrew/homebrew-core", "status", "--porcelain"): r.FakeResponse(stdout=""),
            GIT + (TAPS + "/alice/homebrew-casks", "status", "--porcelain"):
                r.FakeResponse(stdout=" M Casks/sshfs-helper.rb\n"),
        }
        return responses

    def run_inventory(self, responses=None, instance=None, use_brew=True, catalogue=None):
        """Take the inventory of the tree, keeping the runner for the assertions

        @param responses  the probes' answers; None for the canned ones
        @param instance   the instance; None for the tree's own
        @param use_brew   run the `brew` inventory probes
        @param catalogue  the catalogue; None for the fixture's
        @returns          the inventory
        """
        runner = fake(self.tmp, self.responses() if responses is None else responses, self.tree.environ())
        instance = instance or self.tree.instance()
        result = inv_mod.inventory(runner, instance, catalogue or self.catalogue, use_brew=use_brew)
        self.runner = runner
        return result

    @staticmethod
    def by_name(result, kind="formula"):
        """Return the packages of one kind in an inventory, by name

        @param result  the inventory
        @param kind    `formula` or `cask`
        @returns       the packages by name
        """
        return {p.name: p for p in result.packages if p.kind == kind}


class JsonInventoryTest(InventoryCase):
    """The inventory from the `brew info` JSON: formulae, casks, rename links, probes, taps and plain data"""

    def test_package_sets_and_rename_links(self):
        res = self.run_inventory()
        self.assertTrue(res.used_json)
        self.assertIsNone(res.inventory_error)
        self.assertEqual(set(self.by_name(res)), {"jq", "oniguruma", "wget", "postgresql@16", "gitea-runner",
                                                  "libfido2", "cython", "dbus", "alloy-analyzer"})
        self.assertEqual(set(self.by_name(res, "cask")), {"docker-desktop", "appcleaner", "0-ad", "aptible",
                                                          "sshfs-helper", "macfuse-like", "miniconda", "mist",
                                                          "leftover"})
        self.assertEqual([(l.name, l.target) for l in res.cellar_renames], [("alloy", "alloy-analyzer")])
        self.assertEqual(res.cellar_renames[0].resolved, os.path.join(self.tree.prefix, "Cellar", "alloy-analyzer"))
        self.assertEqual([(l.name, l.target) for l in res.caskroom_renames], [("docker", "docker-desktop")])
        self.assertEqual([p.kind for p in res.packages][:9], ["formula"] * 9)

    def test_json_formulae(self):
        f = self.by_name(self.run_inventory())
        jq = f["jq"]
        self.assertEqual((jq.version, jq.requested, jq.linked, jq.active, jq.keg_only),
                         ("1.8.2", True, True, True, False))
        self.assertEqual((jq.origin, jq.homepage, jq.receipt_ok, jq.built_locally),
                         ("homebrew/core", "https://jqlang.org/", True, False))
        self.assertEqual((jq.deps, jq.executables, jq.archs, jq.built_on_os),
                         (["oniguruma"], ["jq"], ["arm64"], "macOS 15.7"))
        self.assertEqual(jq.spec_args, ["jq"])
        self.assertEqual(f["oniguruma"].dependents, ["jq"])
        self.assertFalse(f["oniguruma"].requested)
        wget = f["wget"]
        self.assertEqual(wget.version, "1.25.0_2")
        self.assertFalse(wget.receipt_ok)
        self.assertTrue(wget.pinned and wget.outdated)
        self.assertEqual(wget.executables, ["wget", "wget2"])
        self.assertEqual(wget.deps, ["libidn2", "openssl@3"])
        pg = f["postgresql@16"]
        self.assertEqual((pg.keg_only, pg.linked, pg.active), (True, False, True))

    def test_unmigrated_rename_is_one_package(self):
        res = self.run_inventory()
        runner = self.by_name(res)["gitea-runner"]
        self.assertEqual(runner.version, "0.2.11")
        self.assertEqual(runner.renamed_to, "gitea-runner")
        self.assertEqual(res.kegs["gitea-runner"], [os.path.join(self.tree.prefix, "Cellar", "act_runner", "0.2.11")])
        self.assertNotIn("act_runner", self.by_name(res))

    def test_unmigrated_cask_rename_is_one_cask(self):
        room = os.path.join(self.tree.prefix, "Caskroom")
        os.unlink(os.path.join(room, "docker"))
        os.rename(os.path.join(room, "docker-desktop"), os.path.join(room, "docker"))
        res = self.run_inventory()
        self.assertEqual({"docker", "docker-desktop"} & set(self.by_name(res, "cask")), {"docker-desktop"})
        self.assertEqual(res.caskrooms["docker-desktop"], os.path.join(room, "docker"))
        self.assertEqual((res.rooms()["docker-desktop"], res.rooms()["appcleaner"]), ("docker", "appcleaner"))
        self.assertEqual(inv_mod.HomebrewInventory.from_plain(res.to_plain()).rooms(), res.rooms())

    def test_receipt_only_formula_for_a_rack_not_in_json(self):
        f = self.by_name(self.run_inventory())
        cy = f["cython"]
        self.assertIsNone(cy.requested)          # the receipt lacks installed_on_request
        self.assertEqual((cy.built_locally, cy.origin, cy.deps, cy.archs, cy.built_on_os),
                         (True, "alice/tools", ["libfoo"], ["x86_64"], "macOS 12.6"))
        self.assertEqual(cy.executables, ["cython", "cythonize"])
        self.assertTrue(cy.catalogue_present and cy.receipt_ok)
        self.assertEqual((cy.linked, cy.active, cy.version), (False, False, "3.0.0"))
        dbus = f["dbus"]
        self.assertEqual((dbus.requested, dbus.receipt_ok, dbus.built_locally), (None, False, None))
        self.assertEqual(dbus.homepage, "https://wiki.freedesktop.org/www/Software/dbus")
        alloy = f["alloy-analyzer"]
        self.assertEqual((alloy.linked, alloy.catalogue_present), (True, False))

    def test_casks_from_the_json(self):
        c = self.by_name(self.run_inventory(), "cask")
        docker = c["docker-desktop"]
        self.assertEqual((docker.version, docker.requested, docker.auto_updates), ("4.43.2,199162", True, True))
        self.assertEqual((docker.privileged_install, docker.privileged_uninstall), (True, True))
        self.assertEqual((docker.caskroom_data, docker.executables, docker.receipt_ok), ([], ["docker"], True))
        self.assertEqual(c["0-ad"].version, "0.28.0")
        self.assertEqual((c["0-ad"].privileged_install, c["0-ad"].privileged_uninstall), (False, False))
        self.assertFalse(c["0-ad"].receipt_ok)
        self.assertIsNone(c["0-ad"].requested)
        self.assertEqual((c["aptible"].privileged_install, c["aptible"].privileged_uninstall), (True, True))
        self.assertEqual(c["aptible"].deps, ["libfido2"])
        self.assertEqual(self.by_name(self.run_inventory())["libfido2"].dependents, ["aptible"])
        helper = c["sshfs-helper"]
        self.assertEqual((helper.deps, helper.cask_deps, helper.origin), ([], ["macfuse-like"], "alice/casks"))
        self.assertEqual((helper.privileged_install, helper.privileged_uninstall), (True, False))
        fuse = c["macfuse-like"]
        self.assertEqual((fuse.privileged_install, fuse.privileged_uninstall), (True, True))
        self.assertEqual(fuse.dependents, ["sshfs-helper"])
        cleaner = c["appcleaner"]
        self.assertEqual((cleaner.privileged_install, cleaner.privileged_uninstall), (False, False))

    def test_caskroom_versions_versus_data(self):
        room = os.path.join(self.tree.prefix, "Caskroom")
        for litter in (".DS_Store", "._base"):
            with open(os.path.join(room, "miniconda", litter), "w") as fh:
                fh.write("finder")
        res = self.run_inventory()
        c = self.by_name(res, "cask")
        conda = c["miniconda"]
        self.assertEqual(conda.version, "py314_26.9.4-0")
        self.assertEqual(conda.caskroom_data, [os.path.join(room, "miniconda", "base")])
        leftover = c["leftover"]
        self.assertEqual((leftover.version, leftover.active), ("", False))
        self.assertEqual(leftover.caskroom_data, [os.path.join(room, "leftover", "1.0")])
        self.assertEqual(res.cask_versions["docker-desktop"], ["4.43.2,199162"])
        self.assertNotIn("docker", c)

    def test_newest_cask_version_is_the_one_installed_last(self):
        room = os.path.join(self.tree.prefix, "Caskroom", "0-ad")
        os.makedirs(os.path.join(room, "0.9.0"))
        write(os.path.join(room, ".metadata", "0.9.0", "20990101000000.000", "Casks", "0-ad.json"), "{}")
        res = self.run_inventory(use_brew=False)
        self.assertEqual(res.cask_versions["0-ad"], ["0.28.0", "0.9.0"])
        self.assertEqual(self.by_name(res, "cask")["0-ad"].version, "0.9.0")

    def test_casks_known_only_to_disk_and_catalogue(self):
        c = self.by_name(self.run_inventory(), "cask")
        conda = c["miniconda"]
        self.assertEqual((conda.privileged_install, conda.privileged_uninstall, conda.auto_updates), (True, True, True))
        self.assertEqual((conda.deps, conda.cask_deps, conda.receipt_ok), ([], [], False))
        mist = c["mist"]
        self.assertEqual((mist.privileged_install, mist.privileged_uninstall, mist.auto_updates), (True, True, False))
        self.assertEqual((mist.deps, mist.catalogue_present), ([], False))

    def test_probes_and_raw_facts(self):
        res = self.run_inventory()
        self.assertEqual(res.missing, {"wget": ["libidn2"]})
        self.assertEqual(res.outdated_formulae, {"wget": "1.25.0_3"})
        self.assertEqual(res.pinned, ["wget"])
        self.assertEqual(res.broken_opt_links, [(os.path.join(self.tree.prefix, "opt", "gone"), "../Cellar/gone/1.0")])
        self.assertEqual(res.receiptless_kegs, [os.path.join(self.tree.prefix, "Cellar", "dbus", "1.16.2"),
                                                os.path.join(self.tree.prefix, "Cellar", "wget", "1.24.5")])
        self.assertEqual(res.kegs["wget"], [os.path.join(self.tree.prefix, "Cellar", "wget", v)
                                            for v in ("1.24.5", "1.25.0_2")])
        self.assertEqual(res.root_owned, {})

    def test_brew_env_lines_with_their_file(self):
        res = self.run_inventory()
        prefix_file = os.path.join(self.tree.prefix, "etc", "homebrew", "brew.env")
        user_file = os.path.join(self.tree.home, ".homebrew", "brew.env")
        self.assertEqual([(l.path, l.name, l.value) for l in res.brew_env], [
            (prefix_file, "HOMEBREW_NO_ANALYTICS", "1"), (prefix_file, "HOMEBREW_NO_AUTOREMOVE", ""),
            (prefix_file, "https_proxy", "http://proxy.example:3128"), (prefix_file, "HOMEBREW_NO_SUDO", "1"),
            (user_file, "HOMEBREW_DEVELOPER", "1")])

    def test_taps_with_the_lock_free_git_probe(self):
        res = self.run_inventory()
        taps = {t.name: t for t in res.taps}
        self.assertEqual(set(taps), {"homebrew/core", "alice/casks", "alice/local"})
        self.assertEqual((taps["homebrew/core"].dirty, taps["alice/casks"].dirty), (False, True))
        local = taps["alice/local"]
        self.assertEqual((local.has_git, local.dirty), (False, None))
        git_dirs = [c[5] for c in self.runner.calls if c[:1] == ("/usr/bin/git",)]
        self.assertEqual(len(git_dirs), 2)
        self.assertFalse([d for d in git_dirs if d.endswith("alice/homebrew-local")])

    def test_failed_tap_probe_is_recorded(self):
        responses = self.responses()
        responses[GIT + (TAPS + "/alice/homebrew-casks", "status", "--porcelain")] = r.FakeResponse(
            exit=128, stderr="fatal: not a git repository\n")
        taps = {t.name: t for t in self.run_inventory(responses).taps}
        self.assertIsNone(taps["alice/casks"].dirty)
        self.assertIn("not a git repository", taps["alice/casks"].error)

    def test_round_trip_through_plain_data(self):
        res = self.run_inventory()
        back = inv_mod.HomebrewInventory.from_plain(res.to_plain())
        self.assertEqual(back, res)
        self.assertIsInstance(back.broken_opt_links[0], tuple)
        self.assertIsInstance(back.brew_env[0], locate.EnvLine)


class PrivilegeOnDiskTest(InventoryCase):
    """The privileged flags that launchd jobs, plists, unwritable directories and foreign owners decide"""

    def test_system_launchd_job_privileges_uninstall(self):
        label = "net.freemacsoft.AppCleaner-SmartDelete"
        responses = self.responses()
        responses[("/bin/launchctl", "print", "system/" + label)] = r.FakeResponse(stdout="state = running\n")
        cleaner = self.by_name(self.run_inventory(responses), "cask")["appcleaner"]
        self.assertEqual((cleaner.privileged_install, cleaner.privileged_uninstall), (False, True))
        self.assertEqual(self.runner.calls.count(("/bin/launchctl", "print", "system/" + label)), 1)

    def test_launch_daemon_plist_privileges_uninstall(self):
        write(self.path("LaunchDaemons", "net.freemacsoft.AppCleaner-SmartDelete.plist"), "<plist/>")
        cleaner = self.by_name(self.run_inventory(), "cask")["appcleaner"]
        self.assertTrue(cleaner.privileged_uninstall)

    def test_unwritable_app_directory_privileges_both(self):
        os.chmod(self.tree.appdir, 0o555)
        self.addCleanup(os.chmod, self.tree.appdir, 0o755)
        if os.access(self.tree.appdir, os.W_OK):
            self.skipTest("running as root")
        game = self.by_name(self.run_inventory(), "cask")["0-ad"]
        self.assertEqual((game.privileged_install, game.privileged_uninstall), (True, True))

    def test_bundle_holding_a_file_the_user_does_not_own(self):
        app = os.path.join(self.tree.appdir, "0 A.D..app")
        helper = write(os.path.join(app, "Contents", "MacOS", "helper"), "x")
        with mock.patch.object(cat.os, "lstat", side_effect=root_owned_lstat(helper)):
            game = self.by_name(self.run_inventory(), "cask")["0-ad"]
        self.assertEqual((game.privileged_install, game.privileged_uninstall), (False, True))

    def test_root_owned_keg_paths(self):
        keg_bin = os.path.join(self.tree.prefix, "Cellar", "postgresql@16", "16.10", "bin")
        with mock.patch.object(inv_mod.os, "lstat", side_effect=root_owned_lstat(keg_bin)):
            res = self.run_inventory()
        self.assertEqual(res.root_owned, {"postgresql@16": [keg_bin]})


class DegradedInventoryTest(InventoryCase):
    """The disk-walk inventory when `brew info` fails, `brew missing` errs or no `brew` runs"""

    def test_failed_info_degrades_to_the_disk_walk(self):
        responses = self.responses()
        responses[BREW + ("info", "--json=v2", "--installed")] = r.FakeResponse(
            exit=1, stderr="Error: Failed to download https://formulae.brew.sh/api/formula.jws.json\n")
        instance = self.tree.instance()
        res = self.run_inventory(responses, instance)
        self.assertFalse(res.used_json)
        self.assertIn("Failed to download", res.inventory_error)
        self.assertEqual(instance.inventory_error, res.inventory_error)
        self.assertEqual([c for c in self.runner.calls if c[:3] == BREW], [BREW + ("info", "--json=v2", "--installed")])
        f = self.by_name(res)
        self.assertIn("act_runner", f)
        self.assertEqual(f["act_runner"].renamed_to, "gitea-runner")
        self.assertNotIn("gitea-runner", f)
        self.assertEqual((f["jq"].requested, f["jq"].linked, f["jq"].origin), (True, True, "homebrew/core"))
        self.assertEqual(f["jq"].homepage, self.catalogue.homepage("jq"))
        c = self.by_name(res, "cask")
        docker = c["docker-desktop"]
        self.assertEqual((docker.privileged_install, docker.privileged_uninstall), (True, True))
        self.assertEqual(docker.origin, "homebrew/cask")
        helper = c["sshfs-helper"]
        self.assertEqual((helper.deps, helper.cask_deps), (["libfido2"], ["macfuse-like"]))
        self.assertEqual(self.by_name(res)["libfido2"].dependents, ["aptible", "sshfs-helper"])
        self.assertEqual(c["aptible"].deps, ["libfido2"])        # receipt-less: the catalogue's depends_on_args

    def test_brew_missing_error_sets_the_inventory_error(self):
        responses = self.responses()
        responses[BREW + ("missing",)] = r.FakeResponse(exit=1, stderr="Error: undefined method\n")
        instance = self.tree.instance()
        res = self.run_inventory(responses, instance)
        self.assertTrue(res.used_json)
        self.assertIn("brew missing failed with exit 1", res.inventory_error)
        self.assertEqual(res.missing, {})

    def test_the_summary_says_disk_only_for_a_failed_brew_info_alone(self):
        responses = self.responses()
        responses[BREW + ("outdated", "--json=v2")] = r.FakeResponse(exit=1, stderr="Error: no internet\n")
        instance = self.tree.instance()
        res = self.run_inventory(responses, instance)
        self.assertTrue(res.used_json)
        text = "\n".join(inv_mod.summary_lines([(instance, self.catalogue, res)]))
        self.assertNotIn("inventory from disk only", text)
        self.assertIn("inventory probe failed: brew outdated --json=v2 failed with exit 1", text)
        responses[BREW + ("info", "--json=v2", "--installed")] = r.FakeResponse(exit=1, stderr="Error: no internet\n")
        instance = self.tree.instance()
        res = self.run_inventory(responses, instance)
        text = "\n".join(inv_mod.summary_lines([(instance, self.catalogue, res)]))
        self.assertIn("inventory from disk only: brew info --json=v2 --installed failed with exit 1", text)

    def test_brew_missing_report_with_exit_1_is_no_error(self):
        responses = self.responses()
        responses[BREW + ("missing",)] = r.FakeResponse(exit=1, stdout="libidn2 openssl@3\n")
        res = self.run_inventory(responses)
        self.assertIsNone(res.inventory_error)
        self.assertEqual(res.missing, {"": ["libidn2", "openssl@3"]})

    def test_invalid_json_is_an_inventory_error(self):
        responses = self.responses()
        responses[BREW + ("info", "--json=v2", "--installed")] = r.FakeResponse(stdout="Warning: x\n{")
        res = self.run_inventory(responses)
        self.assertIn("printed no JSON", res.inventory_error)
        self.assertFalse(res.used_json)

    def test_disk_walk_alone_runs_no_brew(self):
        instance = self.tree.instance(inventory_error="earlier")
        res = self.run_inventory(instance=instance, use_brew=False)
        self.assertFalse(res.used_json)
        self.assertEqual([c for c in self.runner.calls if c[:3] == BREW], [])
        self.assertEqual(instance.inventory_error, "earlier")
        self.assertIn("act_runner", self.by_name(res))

    def test_undrivable_instance_runs_no_brew(self):
        instance = self.tree.instance(drivable=False, usability=model.Usability.CANNOT_RUN)
        res = self.run_inventory(instance=instance)
        self.assertEqual([c for c in self.runner.calls if c[:3] == BREW], [])
        self.assertIsNone(res.inventory_error)
        self.assertEqual(len(res.taps), 3)


class CaskroomRenameTest(InventoryCase):
    """A Caskroom rename link whose old token is also a formula's name"""

    def test_formula_named_caskroom_link_is_no_cask(self):
        make_keg(self.tree.prefix, "docker", "29.9.3", receipt("formula-bottle", runtime_dependencies=[]),
                 bins=["docker"])
        res = self.run_inventory(use_brew=False)
        self.assertIn("docker", self.by_name(res))
        self.assertNotIn("docker", self.by_name(res, "cask"))
        self.assertEqual(res.caskroom_renames[0].resolved, os.path.join(self.tree.prefix, "Caskroom",
                                                                        "docker-desktop"))


class ScanTest(InventoryCase):
    """The scan of a located instance: its catalogue, its inventory and the summary lines"""

    def test_scan_locates_loads_and_inventories(self):
        tree = self.tree
        ruby = write(os.path.join(tree.prefix, locate.PORTABLE_RUBY), "", 0o755)
        install_api(tree.cache)
        patcher = mock.patch.object(locate, "ARM64_PREFIX", tree.prefix)
        patcher.start()
        self.addCleanup(patcher.stop)
        ruby_key = ruby.replace(self.tmp, "<tmp>")
        responses = self.responses()
        responses.update({
            (locate.LIPO, "-archs", ruby_key): r.FakeResponse(stdout="arm64\n"),
            ("/usr/bin/arch", "-arm64", ruby_key, "-e", "exit 0"): r.FakeResponse(),
            BREW + ("config",): r.FakeResponse(stdout="HOMEBREW_VERSION: 7.0.11\n"),
            BREW + ("--cache",): r.FakeResponse(stdout=tree.cache + "\n"),
        })
        env = tree.environ()
        with mock.patch.object(locate, "USR_LOCAL", self.path("usr", "local")):
            results = inv_mod.scan(fake(self.tmp, responses, env), env, "arm64")
        self.assertEqual(len(results), 1)
        instance, catalogue, res = results[0]
        self.assertTrue(instance.drivable)
        self.assertEqual(catalogue.source, "api")
        self.assertTrue(res.used_json)
        cellar = os.path.join(tree.prefix, "Cellar")
        version_dirs = sum(len(os.listdir(os.path.join(cellar, rack)))
                           for rack in os.listdir(cellar) if not os.path.islink(os.path.join(cellar, rack)))
        self.assertEqual(sum(len(k) for k in res.kegs.values()), version_dirs)
        text = "\n".join(inv_mod.summary_lines(results))
        self.assertIn(f"Homebrew {tree.prefix} (7.0.11, arm64, catalogue api)", text)
        self.assertIn(f"rename link {os.path.join(cellar, 'alloy')} -> alloy-analyzer", text)
        self.assertIn("tap alice/casks (local changes)", text)
        self.assertIn("tap alice/local (no .git)", text)
        self.assertRegex(text, r"cask\s+miniconda\s+py314_26\.9\.4-0\s+.*data")


class ParserTest(unittest.TestCase):
    """The parsers of `brew deps`, `brew missing` and `brew outdated`, and the launchd owner rule"""

    def test_parse_deps(self):
        self.assertEqual(inv_mod.parse_deps("a: b c\nuser/tap/d: user/tap/e ::xcode\nnot a line\n"),
                         {"a": ["b", "c"], "d": ["e"]})

    def test_parse_missing_both_forms(self):
        self.assertEqual(inv_mod.parse_missing("wget: libidn2 openssl@3\nalice/tap/x: y\n"),
                         {"wget": ["libidn2", "openssl@3"], "x": ["y"]})
        self.assertEqual(inv_mod.parse_missing("libidn2\n"), {"": ["libidn2"]})

    def test_parse_outdated(self):
        formulae, casks = inv_mod.parse_outdated({"formulae": [{"name": "alice/tap/x", "current_version": "2"}],
                                                  "casks": [{"name": "vlc", "current_version": "3.0.21"}]})
        self.assertEqual((formulae, casks), ({"x": "2"}, {"vlc": "3.0.21"}))
        self.assertEqual(inv_mod.parse_outdated(None), ({}, {}))

    def test_service_labels_feed_the_launchd_owner_rule(self):
        labels = fixture_catalogue().service_labels()
        self.assertEqual(services.homebrew_formula("org.freedesktop.dbus-session", labels), "dbus")
        self.assertEqual(services.homebrew_formula("homebrew.mxcl.startx", labels), "xinit")
        self.assertEqual(services.homebrew_formula("sh.brew.mysql", labels), "mysql")
        self.assertIsNone(services.homebrew_formula("com.example.agent", labels))


if __name__ == "__main__":
    unittest.main()

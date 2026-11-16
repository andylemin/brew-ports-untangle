"""The `port` command builders: the argv, sudo, profile and failure policy of each, and their refusals"""

import unittest

from brew_ports import runner as r
from brew_ports.macports import actions
from brew_ports.model import Manager, OnFailure
from tests.unit.helpers import make_instance

PORT = "/opt/local/bin/port"
ARM = [r.ARCH, "-arm64", PORT, "-N"]


class ActionsTest(unittest.TestCase):
    """Every builder of `brew_ports.macports.actions` against an arm64 instance at /opt/local"""

    def setUp(self):
        self.inst = make_instance(Manager.PORTS, prefix="/opt/local", arch="arm64")

    def check(self, action, argv, sudo=True, on_failure=OnFailure.STOP):
        """Assert that an action is a described `port` command of the `ports` profile with the argv given

        @param action      the action a builder returned
        @param argv        the argv it must carry, without `sudo`
        @param sudo        whether it must run as root
        @param on_failure  the failure policy it must carry
        """
        self.assertEqual(action.argv, argv)
        self.assertEqual((action.kind, action.sudo, action.on_failure), ("command", sudo, on_failure))
        self.assertEqual((action.env_profile, action.instance_prefix), ("ports", "/opt/local"))
        self.assertNotIn(r.SUDO, action.argv)
        self.assertTrue(action.description)

    def test_probes(self):
        version = actions.version(self.inst, "arm64", "0.ports.%opt%local.version")
        self.check(version, ARM + ["version"], sudo=False, on_failure=OnFailure.PROBE)
        self.assertTrue(version.read_only)
        self.check(actions.select_summary(self.inst, "arm64", "a"), ARM + ["select", "--summary"], sudo=False,
                   on_failure=OnFailure.PROBE)
        self.check(actions.diagnose(self.inst, "arm64", "a"), ARM + ["diagnose", "--quiet"], sudo=False,
                   on_failure=OnFailure.PROBE)
        repair = actions.version(self.inst, "arm64", "a", sudo=True)
        self.check(repair, ARM + ["version"])
        self.assertFalse(repair.read_only)

    def test_arch_follows_the_instance_and_the_host(self):
        intel = make_instance(Manager.PORTS, prefix="/opt/local", arch="x86_64")
        self.assertEqual(actions.sync(intel, "arm64", "a").argv, [r.ARCH, "-x86_64", PORT, "-N", "sync"])
        self.assertEqual(actions.sync(intel, "x86_64", "a").argv, [PORT, "-N", "sync"])

    def test_install_binary_first_with_a_source_retry(self):
        action = actions.install(self.inst, "arm64", "3.wget.install", "wget", ["+ssl", "-ipv6"], homebrew_present=True)
        self.check(action, ARM + ["-b", "install", "--no-rev-upgrade", "wget", "+ssl", "-ipv6"],
                   on_failure=OnFailure.RETRY_WITH)
        self.assertEqual(action.retry_argv, ARM + ["-t", "install", "--no-rev-upgrade", "wget", "+ssl", "-ipv6"])
        plain = actions.install(self.inst, "arm64", "a", "wget", homebrew_present=False)
        self.assertEqual(plain.retry_argv, ARM + ["install", "--no-rev-upgrade", "wget"])

    def test_install_source_form_for_rollback(self):
        action = actions.install(self.inst, "arm64", "a", "gettext", ["-x11"], homebrew_present=True,
                                 binary_first=False, unrequested=True, on_failure=OnFailure.PROBE)
        self.check(action, ARM + ["-t", "install", "--unrequested", "--no-rev-upgrade", "gettext", "-x11"],
                   on_failure=OnFailure.PROBE)
        self.assertEqual(action.retry_argv, [])

    def test_upgrades(self):
        self.check(actions.upgrade(self.inst, "arm64", "a", "curl", homebrew_present=True),
                   ARM + ["-t", "upgrade", "--no-rev-upgrade", "curl"])
        self.check(actions.upgrade(self.inst, "arm64", "a", "curl", homebrew_present=True, no_deps=True),
                   ARM + ["-n", "-t", "upgrade", "--no-rev-upgrade", "curl"])
        self.check(actions.upgrade(self.inst, "arm64", "a", "curl", homebrew_present=False),
                   ARM + ["upgrade", "--no-rev-upgrade", "curl"])

    def test_forced_upgrade_pair(self):
        action = actions.upgrade_forced(self.inst, "arm64", "2.vim.rebuild", "vim", ["+huge", "-x11"],
                                        homebrew_present=True)
        self.check(action, ARM + ["-n", "-t", "upgrade", "--force", "--no-replace", "--no-rev-upgrade", "vim"],
                   on_failure=OnFailure.RETRY_WITH)
        self.assertEqual(action.retry_argv, ARM + ["-t", "install", "--no-rev-upgrade", "vim", "+huge", "-x11"])
        bare = actions.upgrade_forced(self.inst, "arm64", "a", "vim", homebrew_present=False)
        self.assertEqual(bare.argv, ARM + ["-n", "upgrade", "--force", "--no-replace", "--no-rev-upgrade", "vim"])
        self.assertEqual(bare.retry_argv, ARM + ["install", "--no-rev-upgrade", "vim"])

    def test_uninstall_names_every_version_and_splits_by_port(self):
        specs = [["gettext", "@0.22.5_0"], ["libiconv", "@1.17_0"], ["gettext", "@0.21_1+universal"]]
        action = actions.uninstall(self.inst, "arm64", "5.uninstall.ports", specs, split_order=["gettext", "libiconv"])
        self.check(action, ARM + ["uninstall", "gettext", "@0.22.5_0", "libiconv", "@1.17_0", "gettext",
                                  "@0.21_1+universal"], on_failure=OnFailure.SPLIT)
        self.assertEqual(action.split_head, 5)
        self.assertEqual(r.split_argv(action, "gettext"),
                         ARM + ["uninstall", "gettext", "@0.22.5_0", "gettext", "@0.21_1+universal"])
        self.assertEqual(r.split_argv(action, "libiconv"), ARM + ["uninstall", "libiconv", "@1.17_0"])
        one = actions.uninstall(self.inst, "x86_64", "a", [["zlib", "@1.3.1_0"]], on_failure=OnFailure.STOP)
        self.assertEqual((one.argv, one.split_order, one.split_head), ([PORT, "-N", "uninstall", "zlib", "@1.3.1_0"],
                                                                      ["zlib"], 3))

    def test_uninstall_refusals(self):
        with self.assertRaises(ValueError):
            actions.uninstall(self.inst, "arm64", "a", [])
        with self.assertRaises(ValueError):
            actions.uninstall(self.inst, "arm64", "a", [["zlib", "1.3.1_0"]])
        with self.assertRaises(ValueError):
            actions.uninstall(self.inst, "arm64", "a", [["zlib", "@1.3.1_0"]], split_order=["zlib", "curl"])
        with self.assertRaises(ValueError):
            actions.uninstall(self.inst, "arm64", "a", [["installed", "@x y"]])

    def test_registry_flags_startup_items_and_select(self):
        self.check(actions.setrequested(self.inst, "arm64", "a", ["jq", "gsed"]), ARM + ["setrequested", "jq", "gsed"])
        self.check(actions.load(self.inst, "arm64", "a", "dbus"), ARM + ["load", "dbus"])
        self.check(actions.unload(self.inst, "arm64", "a", "dbus"), ARM + ["unload", "dbus"])
        self.check(actions.select_set(self.inst, "arm64", "7.select.python3", "python3", "python312"),
                   ARM + ["select", "--set", "python3", "python312"])
        self.check(actions.deactivate(self.inst, "arm64", "a", ["vim", "@9.1.0_0+huge"]),
                   ARM + ["-f", "deactivate", "vim", "@9.1.0_0+huge"])
        self.check(actions.activate(self.inst, "arm64", "a", ["vim", "@9.1.0_0+huge"]),
                   ARM + ["-f", "activate", "vim", "@9.1.0_0+huge"])
        self.check(actions.activate(self.inst, "arm64", "a", ["vim", "@9.0.0_0"], force=False),
                   ARM + ["activate", "vim", "@9.0.0_0"])

    def test_snapshots_and_base_maintenance(self):
        self.check(actions.snapshot_create(self.inst, "arm64", "1.ports.%opt%local.snapshot",
                                           "brew-ports 20261112-101500-a1b2c3"),
                   ARM + ["snapshot", "--create", "--note", "brew-ports 20261112-101500-a1b2c3"])
        export = actions.snapshot_export(self.inst, "arm64", "1.ports.%opt%local.export", 7)
        self.check(export, ARM + ["snapshot", "--export", "7"], on_failure=OnFailure.PROBE)
        self.assertTrue(export.read_only)
        self.check(actions.migrate_all(self.inst, "arm64", "a"), ARM + ["migrate", "--all"])
        self.check(actions.selfupdate(self.inst, "arm64", "a"), ARM + ["selfupdate"])
        self.check(actions.sync(self.inst, "arm64", "a"), ARM + ["sync"])

    def test_names_and_tokens_are_checked(self):
        for bad in ("", "-f", "+x11", "@1.0", "two words", "a/b"):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    actions.upgrade(self.inst, "arm64", "a", bad, homebrew_present=False)
        with self.assertRaises(ValueError):
            actions.setrequested(self.inst, "arm64", "a", [])
        with self.assertRaises(ValueError):
            actions.install(self.inst, "arm64", "a", "vim", ["huge"], homebrew_present=False)
        with self.assertRaises(ValueError):
            actions.snapshot_create(self.inst, "arm64", "a", "two\nlines")
        self.assertEqual(actions.upgrade(self.inst, "arm64", "a", "libsigc++", homebrew_present=False).argv[-1],
                         "libsigc++")

    def test_an_instance_without_a_binary_builds_no_command(self):
        gone = make_instance(Manager.PORTS, prefix="/opt/local", binary=None)
        with self.assertRaises(ValueError):
            actions.sync(gone, "arm64", "a")


if __name__ == "__main__":
    unittest.main()

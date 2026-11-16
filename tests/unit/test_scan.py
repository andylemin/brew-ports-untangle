"""Tests of the scan bundle, the `scan.json` round trip and the reuse rules"""

import contextlib
import os
import plistlib
import time
import unittest
from unittest import mock

from brew_ports import runner as r, scan
from brew_ports.env import services as env_services
from brew_ports.homebrew import actions as brew_actions, inventory as brew_inventory
from brew_ports.homebrew.catalogue import Catalogue
from tests.unit.helpers import TempDirTest, make_instance, make_package
from tests.unit.test_runner import QuietConsole


def fake_runner(tmp):
    """Return a fake runner on which every command fails

    @param tmp  the test's temporary directory, which holds the runner's home and output directory
    @returns    the runner
    """
    return r.FakeRunner(default=r.FakeResponse(exit=1), console=QuietConsole(), environ={"HOME": tmp},
                        out_dir=os.path.join(tmp, "out"))


class BuildTest(TempDirTest):
    """Tests of `build`, `write`, `load`, `obtain` and `reusable_scan`"""

    def patched(self, brew_entries):
        """Return patches under which the Homebrew scan yields the given entries and nothing else is found

        @param brew_entries  the entries the Homebrew scan returns
        @returns             an exit stack that holds the patches, for a `with` statement
        """
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch("brew_ports.homebrew.inventory.scan", return_value=brew_entries))
        stack.enter_context(mock.patch("brew_ports.macports.locate.find_instances", return_value=[]))
        stack.enter_context(mock.patch("brew_ports.env.services.inspect", return_value=env_services.ServiceScan()))
        stack.enter_context(mock.patch("brew_ports.env.shell.login_shell", return_value=None))
        return stack

    def brew_entry(self):
        """Return a Homebrew entry with one formula and no catalogue

        @returns  the `(instance, catalogue, inventory)` triple
        """
        inst = make_instance(prefix=self.path("opt", "homebrew"))
        pkg = make_package("wget", prefix=inst.prefix, built_locally=False)
        inv = brew_inventory.HomebrewInventory(instance_prefix=inst.prefix, packages=[pkg])
        return inst, None, inv

    def test_build_keeps_raw_facts_beside_the_packages(self):
        entry = self.brew_entry()
        with self.patched([entry]):
            bundle = scan.build(fake_runner(self.tmp), {"HOME": self.tmp})
        res = bundle.result
        self.assertEqual([i.prefix for i in res.instances], [entry[0].prefix])
        self.assertEqual([p.name for p in res.packages], ["wget"])
        self.assertIn(entry[0].prefix, res.homebrew)
        self.assertNotIn("packages", res.homebrew[entry[0].prefix])

    def test_brew_services_list_corroborates_the_plist_scan(self):
        inst, cat, inv = self.brew_entry()
        plist = "/Library/LaunchDaemons/homebrew.mxcl.dbus.plist"
        runner = fake_runner(self.tmp)
        argv = brew_actions.services_list(inst, runner.host_arch, "0.brew.probe").argv
        runner.responses[runner.key(argv)] = r.FakeResponse(
            stdout=f'[{{"name": "dbus", "status": "started", "file": "{plist}"}}]')
        with mock.patch("brew_ports.homebrew.inventory.scan", return_value=[(inst, cat, inv)]), \
                mock.patch("brew_ports.macports.locate.find_instances", return_value=[]), \
                mock.patch("brew_ports.env.shell.login_shell", return_value=None):
            bundle = scan.build(runner, {"HOME": self.tmp})
        self.assertIn(runner.key(argv), runner.calls)
        self.assertIn(f"brew services ({inst.prefix}) lists {plist} for dbus (started); "
                      "the plist scan did not attribute it there", bundle.notes)

    def test_a_job_under_the_old_label_of_a_renamed_formula(self):
        prefix = self.path("opt", "homebrew")
        keg = os.path.join(prefix, "Cellar", "postgresql@14", "14.15")
        os.makedirs(os.path.join(keg, "bin"))
        os.makedirs(os.path.join(prefix, "opt"))
        os.symlink(keg, os.path.join(prefix, "opt", "postgresql"))
        agents = self.path("Library", "LaunchAgents")
        os.makedirs(agents)
        with open(os.path.join(agents, "homebrew.mxcl.postgresql.plist"), "wb") as fh:
            plistlib.dump({"Label": "homebrew.mxcl.postgresql",
                           "ProgramArguments": [os.path.join(prefix, "opt", "postgresql", "bin", "postgres")]}, fh)
        inst = make_instance(prefix=prefix)
        pkg = make_package("postgresql@14", prefix=prefix, version="14.15", built_locally=False)
        inv = brew_inventory.HomebrewInventory(instance_prefix=prefix, packages=[pkg], kegs={"postgresql@14": [keg]})
        # Homebrew's catalogue makes postgresql an alias of postgresql@18, and no rename names it.
        catalogue = Catalogue(formulae={"postgresql@14": {}, "postgresql@18": {}},
                              formula_aliases={"postgresql": "postgresql@18"}, source="api")
        with mock.patch("brew_ports.homebrew.inventory.scan", return_value=[(inst, catalogue, inv)]), \
                mock.patch("brew_ports.macports.locate.find_instances", return_value=[]), \
                mock.patch("brew_ports.env.shell.login_shell", return_value=None):
            bundle = scan.build(fake_runner(self.tmp), {"HOME": self.tmp})
        svc = next(s for s in bundle.result.services if s.label == "homebrew.mxcl.postgresql")
        self.assertEqual((svc.owned, svc.package, svc.package_kind), (True, "postgresql@14", "formula"))
        self.assertEqual([s.label for s in pkg.services], ["homebrew.mxcl.postgresql"])

    def test_write_load_round_trip_and_reuse_rules(self):
        entry = self.brew_entry()
        sd = self.state_dir()
        run = sd.new_run()
        with self.patched([entry]):
            _, reused = scan.obtain(sd, run, fake_runner(self.tmp), {"HOME": self.tmp})
        self.assertFalse(reused)
        path = scan.reusable_scan(sd)
        if path is None:
            self.fail("the scan just written is not reusable")
        self.assertEqual(path, run.sub("scan.json"))
        loaded = scan.load(path, fake_runner(self.tmp), {"HOME": self.tmp})
        self.assertEqual([p.name for p in loaded.result.packages], ["wget"])
        self.assertEqual(len(loaded.brew), 1)
        self.assertEqual(loaded.brew[0][2].packages[0].name, "wget")
        # Older than ten minutes, or older than the dirty marker: not reused.
        self.assertIsNone(scan.reusable_scan(sd, now=time.time() + scan.REUSE_S + 1))
        old = time.time() - 30
        os.utime(path, (old, old))
        sd.touch_dirty("RUN-X", "apply")
        self.assertIsNone(scan.reusable_scan(sd))

    def test_rescan_never_reuses(self):
        sd = self.state_dir()
        run = sd.new_run()
        with self.patched([]):
            scan.obtain(sd, run, fake_runner(self.tmp), {"HOME": self.tmp})
            _, reused = scan.obtain(sd, sd.new_run(), fake_runner(self.tmp), {"HOME": self.tmp}, rescan=True)
        self.assertFalse(reused)


class HomebrewLookupTest(unittest.TestCase):
    """The racks and Caskroom entries of a Homebrew instance, by a recorded spelling of its prefix"""

    def test_racks_and_caskroom_entries_left_under_old_names(self):
        inst = make_instance(prefix="/opt/homebrew", spellings=("/opt/homebrew", "/private/opt/homebrew"))
        inv = brew_inventory.HomebrewInventory(instance_prefix=inst.prefix,
                                               kegs={"newname": ["/opt/homebrew/Cellar/oldname/1.0"]},
                                               caskrooms={"docker-desktop": "/opt/homebrew/Caskroom/docker"})
        bundle = scan.ScanBundle(result=None, brew=[(inst, None, inv)])
        self.assertEqual(bundle.formula_racks("/private/opt/homebrew"), {"newname": "oldname"})
        self.assertEqual(bundle.cask_rooms("/private/opt/homebrew"), {"docker-desktop": "docker"})
        self.assertEqual((bundle.formula_racks("/usr/local"), bundle.cask_rooms("/usr/local")), ({}, {}))


if __name__ == "__main__":
    unittest.main()

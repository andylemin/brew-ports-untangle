"""`doctor --fix` with the real Homebrew detectors

A keg of a deleted formula is removed only after a terminal answer, and only after the phase 1 snapshot; the
removals queued behind a reinstall of their formula are skipped.
"""

import json
import os
import shutil
import unittest
from unittest import mock

from brew_ports import doctor, runner as r, snapshot, state
from brew_ports.homebrew import health, inventory
from tests.unit.fixtures.doctor import builders as b
from tests.unit.helpers import make_package
from tests.unit.test_homebrew_health_support import GIT_STATUS, NOW, HealthCase, symlink, write


class FixCase(HealthCase):
    """`doctor --fix` over the real Homebrew detectors, its commands answered by `respond`"""

    def setUp(self):
        super().setUp()
        for patcher in (mock.patch.object(health, "_now", return_value=NOW),
                        mock.patch("brew_ports.system.free_bytes", return_value=100 * doctor.GIB)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.sd = state.StateDir(self.path("state"))
        self.ctx = b.context(self.sd)                  # replaced by the context of each fix()

    def fix_run(self) -> state.RunDir:
        """Return the run directory of the last fix

        @returns  its runner's run directory
        """
        run_dir = self.fake.run_dir
        if run_dir is None:
            self.fail("the runner of the fix has no run directory")
        return run_dir

    def respond(self, key):
        """Answer a command of the fix: no `brew doctor` finding, a clean repository, no loaded job, a Brewfile

        @param key  the command's argv
        @returns    the response
        """
        if "doctor" in key or key[:len(GIT_STATUS)] == GIT_STATUS:
            return r.FakeResponse()
        if key[:2] == ("/bin/launchctl", "print"):
            return b.NOT_FOUND
        if "dump" in key:
            path = next(a for a in key if a.startswith("--file="))[len("--file="):]
            with open(path.replace("<run>", self.fix_run().path), "w") as fh:
                fh.write("".join(f'brew "{p.name}"\n' for p in self.inv.packages if p.kind == "formula"))
        return r.FakeResponse()

    def fix(self, answers, tty):
        """Run `brew-ports doctor --fix` over the test's bundle, `--yes` without a terminal

        @param answers  the terminal answers, in order
        @param tty      whether the prompts can be answered
        @returns        the exit code
        """
        def make(ctx, run_dir):
            self.fake = r.FakeRunner(default=self.respond, console=ctx.console, environ=dict(ctx.environ),
                                     run_dir=run_dir)
            return self.fake
        self.ctx = b.context(self.sd, answers, tty=tty, fix=True, yes=not tty)
        with mock.patch("brew_ports.scan.obtain", return_value=(self.bundle(), False)):
            return doctor.cmd_doctor(self.ctx, make_runner=make)


class RealHomebrewHealthTest(FixCase):
    """`doctor --fix` over the real Homebrew detectors and the keg of a deleted formula"""

    def setUp(self):
        super().setUp()
        self.formula("oldtool", known=False)
        self.rack = os.path.join(self.prefix, "Cellar", "oldtool")

    def respond(self, key):
        """Answer a command of the fix; the uninstall removes the rack

        @param key  the command's argv
        @returns    the response
        """
        if "uninstall" in key:
            shutil.rmtree(self.rack)
        return super().respond(key)

    def uninstalls(self):
        """Return the uninstall commands the fix ran

        @returns  their argvs, in order
        """
        return [c for c in self.fake.calls if "uninstall" in c]

    def test_yes_alone_never_removes_the_keg(self):
        self.assertEqual(self.fix([], tty=False), doctor.EXIT_OK)   # the old formula stops no move and works
        self.assertTrue(os.path.isdir(self.rack))
        self.assertEqual(self.uninstalls(), [])
        self.assertIn("\noldtool is installed, but Homebrew's package list does not have it under any name\n"
                      "  Leave it if you still use it.\n"
                      "  Not asked: this is one of the fixes that take your own answer on a terminal.\n",
                      self.ctx.console.text)
        self.assertFalse(os.path.exists(self.sd.dirty_path))

    def test_a_terminal_yes_snapshots_then_removes(self):
        self.assertEqual(self.fix([True], tty=True), doctor.EXIT_OK)
        self.assertEqual(len(self.ctx.asked), 1)
        self.assertEqual(self.uninstalls()[0][-3:], ("--formula", "--force", "oldtool"))
        dump = next(i for i, c in enumerate(self.fake.calls) if "dump" in c)
        self.assertLess(dump, self.fake.calls.index(self.uninstalls()[0]))
        self.assertFalse(os.path.isdir(self.rack))
        formulae = os.path.join(snapshot.brew_dir(self.fix_run(), self.prefix), snapshot.FORMULAE)
        self.assertEqual([f.name for f in snapshot.read_formulae(formulae)], ["oldtool"])
        marker = self.sd.dirty()
        if marker is None:
            self.fail("the fix left no dirty marker")
        self.assertEqual(marker["run_id"], self.fix_run().run_id)


class StaleQueueTest(FixCase):
    """A reinstall of a formula leaves alone the removals the scan queued behind it for that formula

    foo's keg 1.0, linked and named by `opt`, has its receipt; its keg 2.0 has none, and `bin/foo` points at a file
    1.0 lacks.
    """

    def setUp(self):
        super().setUp()
        self.kegs = [self.keg("foo", "1.0"), self.keg("foo", "2.0", receipt=False)]
        self.inv.kegs["foo"] = self.kegs
        self.links = [symlink(os.path.join(self.prefix, *parts, "foo"), self.kegs[0])
                      for parts in (("opt",), ("var", "homebrew", "linked"))]
        self.bin = symlink(os.path.join(self.prefix, "bin", "foo"), "../Cellar/foo/1.0/bin/foo")
        self.formulae["foo"] = {}
        self.inv.packages.append(make_package("foo", prefix=self.prefix, receipt_ok=False, requested=None))

    def respond(self, key):
        """Answer the reinstall as Homebrew does: 2.0 gets its receipt and `bin/foo`, the links move to it, 1.0 goes

        @param key  the command's argv
        @returns    the response
        """
        if "reinstall" in key:
            keg = self.kegs[1]
            write(os.path.join(keg, inventory.RECEIPT), json.dumps({"installed_on_request": True}))
            write(os.path.join(keg, "bin", "foo"))
            for path, target in [(link, keg) for link in self.links] + [(self.bin, "../Cellar/foo/2.0/bin/foo")]:
                os.unlink(path)
                os.symlink(target, path)
            shutil.rmtree(self.kegs[0])
        return super().respond(key)

    def test_a_reinstall_skips_the_removals_queued_behind_it(self):
        exit_code = self.fix([True, True, True], tty=True)
        self.assertEqual(self.ctx.asked, ["Make this fix?"])
        self.assertEqual([c for c in self.fake.calls if health.RM in c], [])
        self.assertEqual(exit_code, doctor.EXIT_OK)             # what was skipped stops no move and is not broken
        self.assertTrue(os.path.isfile(os.path.join(self.kegs[1], inventory.RECEIPT)))
        self.assertTrue(os.path.isfile(self.bin))
        # 2.0 is the newer version: what marks it for deletion is that 1.0 is the one in use, not its age.
        for finding in (f"The link {self.bin} points at a file that is gone",
                        "Version 2.0 of foo is installed but not in use"):
            self.assertIn(f"\nSkipped: {finding}\n  An earlier fix of this run changed foo, so this finding may be "
                          "out of date. `brew-ports doctor` checks again.\n", self.ctx.console.text)


if __name__ == "__main__":
    unittest.main()

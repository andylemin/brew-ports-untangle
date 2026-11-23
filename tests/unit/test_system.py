"""Tests of the macOS facts, free space and path identity"""

import os
import unittest

from brew_ports import runner as r, system
from tests.unit.helpers import TempDirTest
from tests.unit.test_runner import QuietConsole


class IdentityTest(TempDirTest):
    """Tests of path identity, prefix containment and case sensitivity"""

    def test_lies_under_by_identity_through_a_symlink(self):
        prefix = self.path("opt", "homebrew")
        os.makedirs(os.path.join(prefix, "Cellar", "wget"))
        alias = self.path("alias")
        os.symlink(prefix, alias)
        ident = system.identity(prefix)
        if ident is None:
            self.fail(f"{prefix} has no identity")
        self.assertTrue(system.lies_under(os.path.join(alias, "Cellar", "wget"), ident))
        self.assertTrue(system.lies_under(prefix, ident))
        self.assertFalse(system.lies_under(prefix, ident, include_self=False))
        self.assertFalse(system.lies_under(self.path("opt"), ident))
        self.assertTrue(system.same_path(alias, prefix))

    def test_missing_path_has_no_identity(self):
        self.assertIsNone(system.identity(self.path("nope")))

    def test_text_names_prefix(self):
        spellings = ("/opt/homebrew",)
        self.assertTrue(system.text_names_prefix("/opt/homebrew/bin", spellings, False))
        self.assertTrue(system.text_names_prefix("/System/Volumes/Data/opt/homebrew/bin", spellings, False))
        self.assertTrue(system.text_names_prefix("/opt/Homebrew/bin", spellings, True))
        self.assertFalse(system.text_names_prefix("/opt/Homebrew/bin", spellings, False))
        self.assertFalse(system.text_names_prefix("/opt/homebrew-old/bin", spellings, False))

    def test_case_sensitivity_probe_on_this_volume(self):
        d = self.path("CaseProbe")
        os.mkdir(d)
        # Linux test volumes are case-sensitive; macOS default volumes are not.
        expected = os.path.exists(self.path("caseprobe"))
        self.assertEqual(system.case_insensitive(d), expected)


class DsclTest(unittest.TestCase):
    """Tests of the `dscl` record parser"""

    def test_value_on_the_key_line_or_the_next(self):
        self.assertEqual(system.parse_dscl("NFSHomeDirectory: /opt/local/var/macports/home\n"),
                         {"NFSHomeDirectory": "/opt/local/var/macports/home"})
        self.assertEqual(system.parse_dscl("NFSHomeDirectory:\n /Users/with space\n"),
                         {"NFSHomeDirectory": "/Users/with space"})
        self.assertNotIn("NFSHomeDirectory", system.parse_dscl("UserShell: /usr/bin/false\n"))


class FactsTest(TempDirTest):
    """Tests of the system facts and free space"""

    def runner(self, responses):
        """Return a fake runner on which every command not listed fails

        @param responses  the fake responses, by argv tuple
        @returns          the runner
        """
        return r.FakeRunner(responses=responses, default=r.FakeResponse(exit=1), console=QuietConsole(),
                            environ={}, out_dir=self.path("out"))

    def test_rosetta_shell_still_sees_an_arm64_host(self):
        fake = self.runner({(system.SYSCTL, "-n", "hw.optional.arm64"): r.FakeResponse(stdout="1\n"),
                            (system.SYSCTL, "-n", "sysctl.proc_translated"): r.FakeResponse(stdout="1\n")})
        self.assertEqual(system.host_arch(fake), "arm64")
        self.assertTrue(system.rosetta_translated(fake))

    def test_intel_host(self):
        fake = self.runner({(system.SYSCTL, "-n", "hw.optional.arm64"): r.FakeResponse(stdout="0\n")})
        self.assertEqual(system.host_arch(fake), "x86_64")

    def test_facts_survive_missing_tools(self):
        facts = system.facts(self.runner({}))
        self.assertIsNone(facts["macos"])
        self.assertIn(facts["host_arch"], ("arm64", "x86_64"))
        self.assertFalse(facts["clt_receipt"])

    def test_free_bytes(self):
        free = system.free_bytes(self.tmp)
        if free is None:
            self.fail(f"statvfs failed on {self.tmp}")
        self.assertGreater(free, 0)
        self.assertIsNone(system.free_bytes(self.path("nope")))

    def test_a_darwin_major_reads_as_its_macos_release(self):
        self.assertEqual([system.macos_name(major) for major in (19, 20, 24, 25, 26)], [
            "macOS 10.15 (Darwin 19)", "macOS 11 (Darwin 20)", "macOS 15 (Darwin 24)", "macOS 26 (Darwin 25)",
            "macOS 27 (Darwin 26)"])
        # A major with no release that is known gets no guess.
        self.assertEqual((system.macos_name(27), system.macos_name(0)), ("Darwin 27", "Darwin 0"))


if __name__ == "__main__":
    unittest.main()

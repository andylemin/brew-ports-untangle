"""Tests of the command line: help, refusals, exit codes, `scan` and `bootstrap-ports`"""

import contextlib
import io
import json
import os
import unittest
from unittest import mock

from brew_ports import cli, model, state
from tests.unit.helpers import TempDirTest, make_instance

SUBCOMMANDS = ["scan", "doctor", "recommend", "bootstrap-ports", "plan", "apply", "verify", "env-cleanup", "rollback"]


def run_cli(argv, environ=None):
    """Run a command line with its output captured

    @param argv     the arguments after the program name
    @param environ  the environment; None for one that holds only `HOME=/tmp`
    @returns        the exit code, the standard output and the standard error
    """
    out, err = io.StringIO(), io.StringIO()
    code: int | str | None = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv, environ=environ if environ is not None else {"HOME": "/tmp"})
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class HelpTest(unittest.TestCase):
    """Tests of the help text and of the global options on either side of the subcommand"""

    def test_every_subcommand_has_help(self):
        code, top, _ = run_cli(["--help"])
        self.assertEqual(code, 0)
        for name in SUBCOMMANDS:
            self.assertIn(name, top)
            with self.subTest(name=name):
                code, out, _ = run_cli([name, "--help"])
                self.assertEqual(code, 0)
                self.assertIn("usage:", out)

    def test_global_options_before_and_after_subcommand(self):
        parser = cli.build_parser()
        self.assertEqual(parser.parse_args(["--state-dir", "/a", "scan"]).state_dir, "/a")
        self.assertEqual(parser.parse_args(["scan", "--state-dir", "/b"]).state_dir, "/b")
        self.assertIsNone(parser.parse_args(["scan"]).state_dir)
        self.assertTrue(parser.parse_args(["--quiet", "scan"]).quiet)


class RefusalTest(TempDirTest):
    """Tests of the refusals: the brew alias, root, usage errors, a held lock and an unknown run"""

    def test_brew_external_command_alias_is_refused(self):
        for var in ("HOMEBREW_COMMAND", "HOMEBREW_BREW_FILE"):
            code, _, err = run_cli(["scan"], environ={var: "x"})
            self.assertEqual(code, 2)
            self.assertIn("run brew-ports directly", err)

    def test_root_is_refused(self):
        with mock.patch("brew_ports.system.running_as_root", return_value=True):
            code, _, err = run_cli(["--state-dir", self.tmp, "scan"])
        self.assertEqual(code, 3)
        self.assertIn("refuses to run as root", err)

    def test_apply_needs_exactly_one_of_plan_or_resume(self):
        self.assertEqual(run_cli(["apply"])[0], 2)
        self.assertEqual(run_cli(["apply", "p.json", "--resume", "R"])[0], 2)

    def test_remove_manager_with_only_is_a_usage_error(self):
        self.assertEqual(run_cli(["plan", "--target", "brew", "--only", "jq", "--remove-manager"])[0], 2)

    def test_lock_held(self):
        sd = state.StateDir(self.path("state"))
        with mock.patch("brew_ports.system.running_as_root", return_value=False), sd.lock():
            code, _, err = run_cli(["--state-dir", sd.path, "scan"])
        self.assertEqual(code, 3)
        self.assertIn("another brew-ports is running", err)

    def test_every_subcommand_is_wired(self):
        self.assertEqual(sorted(cli.COMMANDS), sorted(SUBCOMMANDS))

    def test_rollback_of_an_unknown_run_is_a_usage_error(self):
        with mock.patch("brew_ports.system.running_as_root", return_value=False):
            code, _, err = run_cli(["--state-dir", self.path("s"), "rollback", "R"])
        self.assertEqual(code, 2)
        self.assertIn("no run R", err)


def no_managers():
    """Keep a CLI test away from the host's own Homebrew, MacPorts and launchd

    @returns  an exit stack that holds the patches, for a `with` statement
    """
    stack = contextlib.ExitStack()
    stack.enter_context(mock.patch("brew_ports.system.running_as_root", return_value=False))
    stack.enter_context(mock.patch("brew_ports.homebrew.inventory.scan", return_value=[]))
    stack.enter_context(mock.patch("brew_ports.macports.locate.find_instances", return_value=[]))
    stack.enter_context(mock.patch("brew_ports.env.services.collect", return_value=[]))
    stack.enter_context(mock.patch("brew_ports.env.shell.login_shell", return_value=None))
    return stack


class ScanTest(TempDirTest):
    """Tests of `scan` through the command line, as JSON and as text"""

    def test_scan_json_writes_scan_json(self):
        with no_managers():
            code, out, _ = run_cli(["--state-dir", self.path("s"), "scan", "--json"],
                                   environ={"HOME": self.tmp, "PATH": "/usr/bin:/bin"})
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("host_arch", data["system"])
        self.assertEqual((data["instances"], data["homebrew"], data["macports"]), ([], {}, {}))
        runs = os.listdir(self.path("s", "runs"))
        self.assertEqual(len(runs), 1)
        self.assertTrue(os.path.exists(self.path("s", "runs", runs[0], "scan.json")))

    def test_scan_text(self):
        with no_managers():
            code, out, _ = run_cli(["--state-dir", self.path("s"), "scan"], environ={"HOME": self.tmp})
        self.assertEqual(code, 0)
        self.assertIn("System", out)


class BootstrapPortsTest(TempDirTest):
    """Tests of `bootstrap-ports`: the refusal over an existing MacPorts, and the dry run"""

    def test_refused_when_macports_exists(self):
        with no_managers(), mock.patch("brew_ports.macports.locate.find_instances",
                                       return_value=[make_instance(model.Manager.PORTS, "/opt/local")]):
            code, _, err = run_cli(["--state-dir", self.path("s"), "bootstrap-ports", "--dry-run"],
                                   environ={"HOME": self.tmp})
        self.assertEqual(code, 3)
        self.assertIn("already installed at /opt/local", err)

    def test_dry_run_prints_the_steps_and_changes_nothing(self):
        with no_managers(), mock.patch("brew_ports.system.macos_version", return_value="15.7.1"):
            code, out, _ = run_cli(["--state-dir", self.path("s"), "bootstrap-ports", "--dry-run"],
                                   environ={"HOME": self.tmp})
        self.assertEqual(code, 0)
        self.assertIn("MacPorts-<version>-15-<name>.pkg", out)
        self.assertFalse(os.path.exists(self.path("s", "dirty")))


if __name__ == "__main__":
    unittest.main()

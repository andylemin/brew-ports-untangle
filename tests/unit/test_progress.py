"""Tests of the activity line: what it shows, when it is drawn, and how it keeps out of the other output"""

import argparse
import io
import os
import tempfile
import time
import unittest
from unittest import mock

from brew_ports import progress, report, runner as runner_mod, state as state_mod, system
from brew_ports.context import Context
from tests.unit.helpers import TempDirTest


class TerminalStream(io.StringIO):
    """A UTF-8 text stream that says it is a terminal"""

    encoding = "utf-8"

    def isatty(self):
        """Return that the stream is a terminal

        @returns  True
        """
        return True


class Clock:
    """A clock the test moves by hand"""

    def __init__(self):
        """Start at an arbitrary time"""
        self.now = 1000.0

    def __call__(self):
        """Return the time

        @returns  the time the test set
        """
        return self.now


class ActivityTest(unittest.TestCase):
    """Tests of the line's text, its width, its redraws and what clears or holds it"""

    def setUp(self):
        self.clock = Clock()
        self.out = TerminalStream()
        self.line = progress.Activity(self.out, clock=self.clock, columns=lambda: 120)
        self.addCleanup(setattr, progress.Activity, "current", None)
        progress.Activity.current = self.line

    def test_the_line_names_the_step_and_its_age(self):
        progress.step("doctor")
        self.clock.now += 12.6
        self.line.draw()
        self.assertEqual(self.out.getvalue(), progress.CLEAR + "⠙ doctor (12 s)")

    def test_the_count_and_the_running_command_follow_the_step(self):
        progress.step("Homebrew /usr/local: checking installed files")
        progress.counting("files")
        progress.count(48213)
        with progress.running("installed formulae and casks"):
            self.assertEqual(self.line.text(), "Homebrew /usr/local: checking installed files: 48,213 files, "
                                               "installed formulae and casks (0 s)")
        self.assertEqual(self.line.text(), "Homebrew /usr/local: checking installed files: 48,213 files (0 s)")

    def test_a_known_total_reads_done_of_total(self):
        progress.step("matching packages")
        progress.counting("packages", 412)
        progress.count(37)
        self.clock.now += 65
        self.assertEqual(self.line.text(), "matching packages: 37 of 412 packages (1:05)")

    def test_a_new_step_starts_its_age_and_its_count_again(self):
        progress.step("services")
        progress.counting("files")
        progress.count(5)
        self.clock.now += 30
        progress.step("linked libraries")
        self.assertEqual(self.line.text(), "linked libraries (0 s)")

    def test_the_line_is_cut_to_the_terminal_width(self):
        line = progress.Activity(self.out, clock=self.clock, columns=lambda: 30)
        line.step("MacPorts /opt/local: looking for unregistered files")
        line.draw()
        drawn = self.out.getvalue()[len(progress.CLEAR):]
        self.assertEqual(len(drawn), 29)
        self.assertTrue(drawn.endswith("..."))

    def test_a_terminal_that_reports_no_width_counts_as_80_columns(self):
        with tempfile.TemporaryFile("w+") as stream, \
                mock.patch("brew_ports.progress.os.get_terminal_size", return_value=os.terminal_size((0, 0))):
            self.assertEqual(progress._columns(stream), 80)

    def test_a_stream_that_is_not_utf8_gets_an_ascii_spinner(self):
        class Ascii(TerminalStream):
            """A terminal stream in ASCII"""

            encoding = "US-ASCII"

        out = Ascii()
        line = progress.Activity(out, clock=self.clock, columns=lambda: 80)
        line.step("scan")
        line.draw()
        self.assertEqual(out.getvalue(), progress.CLEAR + "/ scan (0 s)")

    def test_a_console_write_clears_the_line_first(self):
        console = report.Console(stream=TerminalStream(), err=self.out)
        console.activity = self.line
        progress.step("scan")
        self.line.draw()
        console.warn("a warning")
        self.assertEqual(self.out.getvalue(), progress.CLEAR + "⠙ scan (0 s)" + progress.CLEAR + "a warning\n")

    def test_a_held_line_stays_off_the_terminal_until_the_block_ends(self):
        progress.step("plan")
        self.line.draw()
        with progress.held():
            self.line.draw()
        self.assertEqual(self.out.getvalue(), progress.CLEAR + "⠙ plan (0 s)" + progress.CLEAR)
        self.line.draw()
        self.assertTrue(self.out.getvalue().endswith(progress.CLEAR + "⠹ plan (0 s)"))

    def test_the_line_is_redacted_as_the_console_redacts(self):
        console = report.Console(stream=TerminalStream(), err=self.out, redact=True,
                                 redactor=report.Redactor(home="/Users/alice", user="alice"))
        line = progress.Activity(self.out, console.redacted, clock=self.clock, columns=lambda: 120)
        line.step("shell setup")
        line.command = "shell file /Users/alice/.zprofile"
        line.draw()
        self.assertIn("shell file ~/.zprofile", self.out.getvalue())
        self.assertNotIn("alice", self.out.getvalue())


class TickerTest(unittest.TestCase):
    """Tests of the ticker thread, which redraws the line through work that calls nothing"""

    def test_the_ticker_redraws_while_the_tool_works_between_calls(self):
        out = TerminalStream()
        line = progress.Activity(out, columns=lambda: 80)
        line.step("linked libraries")
        line.start()
        try:
            end = time.monotonic() + 0.6
            while time.monotonic() < end:
                pass
        finally:
            line.close()
        self.assertGreaterEqual(out.getvalue().count("linked libraries"), 2)
        self.assertTrue(out.getvalue().endswith(progress.CLEAR))
        self.assertFalse(line._thread.is_alive())


class ShownTest(unittest.TestCase):
    """Tests of when a command draws the line, and of the calls without one"""

    def tearDown(self):
        progress.Activity.current = None

    def test_a_terminal_draws_unless_quiet_dumb_or_piped(self):
        with tempfile.TemporaryFile("w+") as regular:
            self.assertTrue(progress.wanted(report.Console(stream=regular, err=TerminalStream()), {}))
            self.assertFalse(progress.wanted(report.Console(stream=regular, err=TerminalStream(), quiet=True), {}))
            self.assertFalse(progress.wanted(report.Console(stream=regular, err=TerminalStream()), {"TERM": "dumb"}))
            self.assertFalse(progress.wanted(report.Console(stream=regular, err=io.StringIO()), {}))
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd) as _reader, os.fdopen(write_fd, "w") as pipe:
            self.assertFalse(progress.wanted(report.Console(stream=pipe, err=TerminalStream()), {}))

    def test_shown_draws_for_the_block_and_erases_the_line_after(self):
        err = TerminalStream()
        with tempfile.TemporaryFile("w+") as regular:
            console = report.Console(stream=regular, err=err)
            with progress.shown(console, "doctor", {}):
                self.assertIs(console.activity, progress.Activity.current)
                time.sleep(0.3)
            self.assertIsNone(console.activity)
        self.assertIsNone(progress.Activity.current)
        self.assertIn("doctor (0 s)", err.getvalue())
        self.assertTrue(err.getvalue().endswith(progress.CLEAR))

    def test_without_a_terminal_shown_draws_nothing(self):
        out, err = io.StringIO(), io.StringIO()
        console = report.Console(stream=out, err=err)
        with progress.shown(console, "doctor", {}):
            self.assertIsNone(progress.Activity.current)
            progress.step("services")
            progress.counting("files", 3)
            progress.count()
            with progress.running("launchd job"), progress.held():
                console.out("output")
        self.assertEqual(out.getvalue(), "output\n")
        self.assertEqual(err.getvalue(), "")


class CallersTest(TempDirTest):
    """Tests of the prompts and the runner, which hold the line or name the running command"""

    def setUp(self):
        super().setUp()
        self.line = progress.Activity(TerminalStream(), columns=lambda: 80)
        progress.Activity.current = self.line
        self.addCleanup(setattr, progress.Activity, "current", None)

    def test_a_prompt_holds_the_line_while_it_waits(self):
        ctx = Context(argparse.Namespace(yes=False), report.Console(stream=io.StringIO(), err=io.StringIO()),
                      state_mod.StateDir(self.tmp), tty=True, environ={})
        holds = []
        replies = iter(["y", "keep"])

        def answer(_prompt):
            holds.append(self.line._holds)
            return next(replies)

        with mock.patch("builtins.input", answer):
            self.assertTrue(ctx.ask_terminal("Go on?", False))
            self.assertEqual(ctx.choose("Keep it?", ("keep", "drop"), "keep"), "keep")
        self.assertEqual(holds, [1, 1])
        self.assertEqual(self.line._holds, 0)

    def test_the_runner_names_the_command_while_it_runs(self):
        seen = []

        def respond(_key):
            seen.append(self.line.command)
            return runner_mod.FakeResponse(stdout="15.5\n")

        fake = runner_mod.FakeRunner(default=respond, console=report.Console(stream=io.StringIO(),
                                                                             err=io.StringIO()),
                                     environ={}, out_dir=self.tmp)
        fake.run(system.probe("sw_vers", ["/usr/bin/sw_vers", "-productVersion"], "macOS version"))
        self.assertEqual(seen, ["macOS version"])
        self.assertEqual(self.line.command, "")


if __name__ == "__main__":
    unittest.main()

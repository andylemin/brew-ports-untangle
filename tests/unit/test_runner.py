"""Tests of the runner: environment profiles, argv builders, failure policies, sudo, output files and signals"""

import io
import os
import signal
import sys
import unittest
from collections.abc import Sequence
from unittest import mock

from brew_ports import model, runner as r
from brew_ports.report import Console
from tests.unit.helpers import TempDirTest


def act(action_id="3.x.step", argv=None, **kw):
    """Return a command action for the runner tests

    @param action_id  the action's id
    @param argv       the command; None for `/bin/true`
    @param kw         `Action` fields that override the defaults
    @returns          the action
    """
    base = {"action_id": action_id, "kind": "command", "argv": argv or ["/bin/true"], "sudo": False,
            "description": "d"}
    base.update(kw)
    return model.Action(**base)


class QuietConsole(Console):
    """A console that writes into memory, for tests that must print nothing"""

    def __init__(self):
        """Start the console on two in-memory streams"""
        super().__init__(stream=io.StringIO(), err=io.StringIO())


class ProfileTest(unittest.TestCase):
    """Tests of the `brew`, `ports` and `neutral` environment profiles"""

    ENV = {
        "HOME": "/Users/u", "PATH": "/opt/homebrew/bin:/usr/bin", "LANG": "en_AU.UTF-8", "LC_ALL": "C",
        "https_proxy": "http://p:3128", "no_proxy": "localhost", "DYLD_LIBRARY_PATH": "/opt/local/lib",
        "PYTHONPATH": "/x", "MANPATH": "/m", "HOMEBREW_CASK_OPTS": "--appdir=~/Apps",
        "HOMEBREW_DEVELOPER": "1", "HOMEBREW_BUNDLE_FILE": "/b", "HOMEBREW_NO_SUDO": "0",
        "HOMEBREW_UPGRADE_GREEDY_CASKS": "x", "SSH_TTY": "/dev/ttys001", "XDG_CONFIG_HOME": "/c",
    }

    def test_brew_profile(self):
        env = r.profile_env("brew", self.ENV, prefix="/opt/homebrew")
        self.assertEqual(env["PATH"], "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertEqual(env["HOMEBREW_NO_SUDO"], "1")
        self.assertEqual(env["HOMEBREW_CASK_OPTS"], "--appdir=~/Apps")
        for gone in ("HOMEBREW_DEVELOPER", "HOMEBREW_BUNDLE_FILE", "HOMEBREW_UPGRADE_GREEDY_CASKS",
                     "DYLD_LIBRARY_PATH", "PYTHONPATH", "MANPATH"):
            self.assertNotIn(gone, env)
        for kept in ("HOME", "LANG", "LC_ALL", "https_proxy", "no_proxy", "SSH_TTY", "XDG_CONFIG_HOME"):
            self.assertIn(kept, env)

    def test_ports_and_neutral_profiles_drop_homebrew(self):
        ports = r.profile_env("ports", self.ENV, prefix="/opt/local")
        self.assertEqual(ports["COLUMNS"], "200")
        self.assertTrue(ports["PATH"].startswith("/opt/local/bin:/opt/local/sbin:"))
        neutral = r.profile_env("neutral", self.ENV)
        self.assertEqual(neutral["PATH"], r.SYSTEM_PATH)
        for env in (ports, neutral):
            self.assertFalse([k for k in env if k.startswith("HOMEBREW_")])

    def test_unknown_profile(self):
        with self.assertRaises(ValueError):
            r.profile_env("other", {})


class ArgvHelpersTest(unittest.TestCase):
    """Tests of the sudo, arch, curl and `SPLIT` argv builders and of the name check"""

    def test_sudo_argv_names_variables_never_values(self):
        argv = r.sudo_argv(["/opt/local/bin/port", "-N", "sync"], {"https_proxy": "http://u:pw@p"}, False)
        self.assertEqual(argv[:4], [r.SUDO, "-n", "--preserve-env=https_proxy", "--"])
        self.assertNotIn("pw", " ".join(argv))
        self.assertEqual(r.sudo_argv(["x"], {}, False), [r.SUDO, "-n", "--", "x"])
        self.assertEqual(r.sudo_argv(["x"], {"https_proxy": "p"}, True), [r.SUDO, "-n", "--", "x"])

    def test_arch_argv(self):
        self.assertEqual(r.arch_argv("x86_64", "arm64", ["/usr/local/bin/brew"]),
                         [r.ARCH, "-x86_64", "/usr/local/bin/brew"])
        self.assertEqual(r.arch_argv("x86_64", "x86_64", ["b"]), ["b"])

    def test_require_names(self):
        with self.assertRaises(ValueError):
            r.require_names([])
        with self.assertRaises(ValueError):
            r.require_names([""])
        self.assertEqual(r.require_names(["a"]), ["a"])

    def test_curl_argv(self):
        argv = r.curl_argv("https://api.github.com/x", "/tmp/o", user_agent="brew-ports/0.1")
        self.assertEqual(argv[:2], [r.CURL, "-q"])
        self.assertIn("=https", argv)
        self.assertEqual(argv[-1], "https://api.github.com/x")
        with self.assertRaises(ValueError):
            r.curl_argv("http://x", "/tmp/o")

    def test_split_argv(self):
        brew = act(argv=["brew", "uninstall", "--formula", "--force", "a", "b"], split_order=["a", "b"], split_head=4)
        self.assertEqual(r.split_argv(brew, "b"), ["brew", "uninstall", "--formula", "--force", "b"])
        port = act(argv=["port", "-N", "uninstall", "foo", "@1_0", "bar", "@2_0", "foo", "@3_0"],
                   split_order=["bar", "foo"], split_head=3)
        self.assertEqual(r.split_argv(port, "foo"), ["port", "-N", "uninstall", "foo", "@1_0", "foo", "@3_0"])
        with self.assertRaises(ValueError):
            r.split_argv(port, "baz")


class PolicyTest(TempDirTest):
    """Tests of the failure policies, deferred results and cleanup blocks"""

    def runner(self, responses, **kw):
        """Return a fake runner in phase 3 of a new run

        @param responses  the canned responses, by argv
        @param kw         further `FakeRunner` arguments
        @returns          the runner and its run directory
        """
        run = self.state_dir().new_run()
        fake = r.FakeRunner(responses=responses, run_dir=run, console=QuietConsole(), environ={"HOME": "/h"}, **kw)
        fake.phase = 3
        return fake, run

    def test_stop_raises_and_records_failure(self):
        fake, run = self.runner({("/bin/x",): r.FakeResponse(exit=2)})
        with self.assertRaises(r.ActionFailed):
            fake.run(act(argv=["/bin/x"]))
        self.assertEqual(run.journal.result(3, "3.x.step"), "failed")

    def test_a_failure_names_the_command_and_its_error_line(self):
        argv = ("/usr/bin/arch", "-arm64", "/opt/homebrew/bin/brew", "install", "--formula", "nosuch")
        stderr = "Warning: something else\nError: No available formula with the name \"nosuch\".\nmore detail\n"
        fake, _ = self.runner({argv: r.FakeResponse(exit=1, stderr=stderr)})
        with self.assertRaises(r.ActionFailed) as caught:
            fake.run(act(argv=list(argv)))
        self.assertEqual(str(caught.exception), "`/opt/homebrew/bin/brew install --formula nosuch` failed (exit 1): "
                                                "Error: No available formula with the name \"nosuch\".")

    def test_a_failure_without_an_error_line_gives_the_last_line(self):
        fake, _ = self.runner({("/bin/x",): r.FakeResponse(exit=2, stdout="first\nlast\n"),
                               ("/bin/y",): r.FakeResponse(exit=3)})
        with self.assertRaises(r.ActionFailed) as caught:
            fake.run(act(argv=["/bin/x"]))
        self.assertEqual(str(caught.exception), "`/bin/x` failed (exit 2): last")
        with self.assertRaises(r.ActionFailed) as caught:
            fake.run(act(argv=["/bin/y"]))
        self.assertEqual(str(caught.exception), "`/bin/y` failed (exit 3)")

    def test_probe_returns_status_and_no_result_line(self):
        fake, run = self.runner({("/bin/x",): r.FakeResponse(exit=1, stdout="data")})
        res = fake.run(act(argv=["/bin/x"], on_failure=model.OnFailure.PROBE, read_only=True))
        self.assertEqual((res.exit, res.stdout()), (1, "data"))
        self.assertIsNone(run.journal.result(3, "3.x.step"))

    def test_split_retries_each_name(self):
        fake, run = self.runner({
            ("brew", "install", "a", "b", "c"): r.FakeResponse(exit=1),
            ("brew", "install", "a"): r.FakeResponse(exit=0),
            ("brew", "install", "b"): r.FakeResponse(exit=1),
            ("brew", "install", "c"): r.FakeResponse(exit=0),
        })
        res = fake.run(act(argv=["brew", "install", "a", "b", "c"], on_failure=model.OnFailure.SPLIT,
                           split_order=["a", "b", "c"], split_head=2))
        self.assertEqual(res.failed, ["b"])
        self.assertFalse(res.ok)
        ids = [e["action_id"] for e in run.journal.entries() if "argv" in e]
        self.assertEqual(ids, ["3.x.step", "3.x.step.a", "3.x.step.b", "3.x.step.c"])
        self.assertEqual(run.journal.result(3, "3.x.step"), "failed")

    def test_retry_that_passes_makes_the_action_ok(self):
        fake, run = self.runner({("p", "upgrade"): r.FakeResponse(exit=1), ("p", "install"): r.FakeResponse(exit=0)})
        res = fake.run(act(argv=["p", "upgrade"], on_failure=model.OnFailure.RETRY_WITH, retry_argv=["p", "install"]))
        self.assertTrue(res.ok)
        self.assertEqual(res.retry.action_id, "3.x.step.retry")
        self.assertEqual(run.journal.result(3, "3.x.step"), "ok")

    def test_deferred_result_waits_for_the_post_check(self):
        fake, run = self.runner({("p",): r.FakeResponse(exit=0)})
        a = act(argv=["p"])
        fake.run(a, defer_result=True)
        self.assertIsNone(run.journal.result(3, "3.x.step"))
        fake.record_result(a, False)
        self.assertEqual(run.journal.result(3, "3.x.step"), "failed")

    def test_cleanup_runs_commands_after_an_interrupt(self):
        fake, _ = self.runner({("launchctl", "bootstrap"): r.FakeResponse(exit=0)})
        fake.interrupted = True
        with self.assertRaises(r.Interrupted):
            fake.run(act(argv=["launchctl", "bootstrap"]))
        with fake.cleanup():
            self.assertEqual(fake.run(act(argv=["launchctl", "bootstrap"])).exit, 0)
        with self.assertRaises(r.Interrupted):
            fake.check_interrupt()

    def test_manual_and_non_command_actions_are_refused(self):
        fake, _ = self.runner({})
        with self.assertRaises(ValueError):
            fake.run(act(manual=True))
        with self.assertRaises(ValueError):
            fake.run(act(kind="note"))


class SudoRuleTest(TempDirTest):
    """Tests of sudo failures, the `--preserve-env` refusal and the keepalive"""

    def runner(self, responses):
        """Return a fake runner in phase 3 of a new run, with a proxy variable in its environment

        @param responses  the canned responses, by argv
        @returns          the runner
        """
        run = self.state_dir().new_run()
        fake = r.FakeRunner(responses=responses, run_dir=run, console=QuietConsole(),
                            environ={"HOME": "/h", "https_proxy": "http://proxy:3128"})
        fake.phase = 3
        return fake

    def test_sudo_failure_escalates_whatever_the_policy(self):
        fake = self.runner({(r.SUDO, "-n", "--preserve-env=https_proxy", "--", "/opt/local/bin/port", "-N", "sync"):
                            r.FakeResponse(exit=1, stderr="sudo: a password is required\n")})
        with self.assertRaises(r.EscalationFailed):
            fake.run(act(argv=["/opt/local/bin/port", "-N", "sync"], sudo=True, on_failure=model.OnFailure.PROBE,
                         env_profile="ports", instance_prefix="/opt/local"))

    def test_preserve_env_refusal_reruns_without_it(self):
        fake = self.runner({
            (r.SUDO, "-n", "--preserve-env=https_proxy", "--", "/bin/x"):
                r.FakeResponse(exit=1, stderr="sudo: sorry, you are not allowed to preserve the environment\n"),
            (r.SUDO, "-n", "--", "/bin/x"): r.FakeResponse(exit=0),
            (r.SUDO, "-n", "--", "/bin/y"): r.FakeResponse(exit=0),
        })
        fake.run(act(argv=["/bin/x"], sudo=True))
        self.assertTrue(fake.preserve_env_refused)
        self.assertEqual(len(fake.notes), 1)
        fake.run(act(action_id="3.y.step", argv=["/bin/y"], sudo=True))
        self.assertEqual(fake.calls[-1], (r.SUDO, "-n", "--", "/bin/y"))

    def test_keepalive_runs_before_a_sudo_command(self):
        fake = self.runner({(r.SUDO, "-n", "--preserve-env=https_proxy", "--", "/bin/x"): r.FakeResponse(exit=0)})
        fake.sudo_ready = True
        fake._last_keepalive = float("-inf")
        fake.run(act(argv=["/bin/x"], sudo=True))
        self.assertIn((r.SUDO, "-n", "-v"), fake.calls)

    def test_failed_keepalive_stops_sudo_commands(self):
        fake = self.runner({(r.SUDO, "-n", "--preserve-env=https_proxy", "--", "/bin/x"): r.FakeResponse(exit=0)})
        fake.sudo_ready = True
        fake.sudo_ok = False
        fake._last_keepalive = float("-inf")
        fake.keepalive()
        with self.assertRaises(r.EscalationFailed):
            fake.run(act(argv=["/bin/x"], sudo=True))


class StdoutChannelTest(TempDirTest):
    """Tests of an action whose standard output goes to its destination file"""

    def test_success_renames_and_failure_keeps_the_partial(self):
        run = self.state_dir().new_run()
        dst = run.sub("data-archive", "%opt%local%var.tar.gz")
        responses: dict[Sequence[str], r.Responder] = {
            ("tar",): [r.FakeResponse(exit=0, stdout="A"), r.FakeResponse(exit=2, stdout="B")]}
        fake = r.FakeRunner(responses=responses, run_dir=run, console=QuietConsole(), environ={})
        res = fake.run(act(argv=["tar"], dst=dst))
        self.assertEqual(res.stdout_path, dst)
        self.assertEqual(res.stdout(), "A")
        res2 = fake.run(act(argv=["tar"], dst=dst, on_failure=model.OnFailure.PROBE))
        self.assertEqual(res2.stdout_path, dst + ".partial")
        with open(dst) as fh:
            self.assertEqual(fh.read(), "A")

    def test_leftover_partial_is_deleted_first(self):
        run = self.state_dir().new_run()
        dst = run.sub("x.tar.gz")
        with open(dst + ".partial", "w") as fh:
            fh.write("stale")
        fake = r.FakeRunner(responses={("tar",): r.FakeResponse(exit=0, stdout="new")}, run_dir=run,
                            console=QuietConsole(), environ={})
        fake.run(act(argv=["tar"], dst=dst))
        with open(dst) as fh:
            self.assertEqual(fh.read(), "new")


class FakeRunnerTest(TempDirTest):
    """Tests of the fake runner's placeholders and of a command it has no response for"""

    def test_placeholders(self):
        run = self.state_dir().new_run()
        fake = r.FakeRunner(responses={("cp", "<run>/a", "<id>"): r.FakeResponse()}, run_dir=run,
                            console=QuietConsole(), environ={})
        fake.run(act(argv=["cp", run.sub("a"), run.run_id]))
        with self.assertRaises(KeyError):
            fake.run(act(argv=["unknown"]))


class CommandRunnerTest(TempDirTest):
    """Tests of real children: process groups, sessions, timeouts and forwarded interrupts"""

    def runner(self):
        """Return a command runner in phase 0 of a new run

        @returns  the runner
        """
        run = self.state_dir().new_run()
        cr = r.CommandRunner(run_dir=run, console=QuietConsole(), environ={"HOME": self.tmp})
        cr.phase = 0
        return cr

    def test_child_gets_its_own_group_in_the_same_session(self):
        cr = self.runner()
        code = "import os; print(os.getpgid(0), os.getsid(0), os.getpid())"
        res = cr.run(act(argv=[sys.executable, "-c", code], read_only=True, on_failure=model.OnFailure.PROBE))
        pgid, sid, pid = map(int, res.stdout().split())
        self.assertEqual(pgid, pid)
        self.assertEqual(sid, os.getsid(0))
        self.assertNotEqual(pgid, os.getpgid(0))
        self.assertNotIn("start_new_session", r._group_kwargs())

    def test_new_session_probe_for_the_login_shell(self):
        cr = self.runner()
        code = "import os; print(os.getsid(0), os.getpid())"
        res = cr.run(act(argv=[sys.executable, "-c", code], read_only=True, on_failure=model.OnFailure.PROBE,
                         new_session=True))
        sid, pid = map(int, res.stdout().split())
        self.assertEqual(sid, pid)
        with self.assertRaises(ValueError):
            cr.run(act(argv=["/bin/true"], new_session=True))
        with self.assertRaises(ValueError):
            cr.run(act(argv=["/bin/true"], read_only=True, sudo=True, new_session=True))

    def test_missing_program_is_exit_127(self):
        cr = self.runner()
        res = cr.run(act(argv=["/nonexistent/prog"], read_only=True, on_failure=model.OnFailure.PROBE))
        self.assertEqual(res.exit, 127)
        self.assertIn("/nonexistent/prog", res.stderr())

    def test_probe_timeout_kills_the_group(self):
        cr = self.runner()
        res = cr.run(act(argv=[sys.executable, "-c", "import time; time.sleep(30)"], read_only=True,
                         on_failure=model.OnFailure.PROBE, timeout_s=1))
        self.assertTrue(res.timed_out)
        self.assertNotEqual(res.exit, 0)

    def test_sigint_forwarded_and_child_waited_for(self):
        cr = self.runner()
        script = ("import signal, sys, time\n"
                  "signal.signal(signal.SIGINT, lambda *a: sys.exit(7))\n"
                  "print('ready', flush=True)\n"
                  "time.sleep(30)\n")
        previous = signal.signal(signal.SIGALRM, lambda *a: cr.note_sigint())
        self.addCleanup(signal.signal, signal.SIGALRM, previous)
        signal.setitimer(signal.ITIMER_REAL, 0.5)
        res = cr.run(act(argv=[sys.executable, "-c", script], on_failure=model.OnFailure.PROBE))
        self.assertEqual(res.exit, 7)
        with self.assertRaises(r.Interrupted):
            cr.check_interrupt()

    def test_earlier_interrupt_not_forwarded_to_cleanup(self):
        cr = self.runner()
        cr.note_sigint()
        script = ("import signal, sys, time\n"
                  "signal.signal(signal.SIGINT, lambda *a: sys.exit(7))\n"
                  "time.sleep(1.5)\n")
        with cr.cleanup():
            res = cr.run(act(argv=[sys.executable, "-c", script], on_failure=model.OnFailure.PROBE))
        self.assertEqual(res.exit, 0)
        with self.assertRaises(r.Interrupted):
            cr.check_interrupt()

    def test_sudo_interrupt_uses_a_root_kill(self):
        cr = self.runner()
        seen = []

        def root_kill(argv):
            seen.append(argv)
            return 0

        with mock.patch.object(cr, "_probe", side_effect=root_kill):
            cr._forward_interrupt(act(sudo=True), 12345, "5.uninstall.ports")
        self.assertEqual(seen, [[r.SUDO, "-n", r.KILL, "-s", "INT", "--", "-12345"]])
        ids = [e["action_id"] for e in cr.run_dir.journal.entries()]
        self.assertIn("5.uninstall.ports.interrupt", ids)


class RootFilesTest(TempDirTest):
    """Tests of the root staging directory's ownership check"""

    def test_staging_dir_not_owned_by_root_is_refused(self):
        run = self.state_dir().new_run()
        fake = r.FakeRunner(default=r.FakeResponse(exit=0), run_dir=run, console=QuietConsole(), environ={})
        fake.phase = 7
        files = r.RootFiles(fake, run.run_id)
        with mock.patch.object(files, "STAGING_PARENT", self.tmp), \
                mock.patch("secrets.token_hex", return_value="feedface"):
            os.mkdir(self.path("brew-ports.feedface"), 0o755)
            with self.assertRaises(r.StagingError):
                files.staging_dir()
        self.assertEqual(fake.calls[0][-1], self.path("brew-ports.feedface"))

    def test_a_copy_the_store_holds_already_stands(self):
        run = self.state_dir().new_run()
        copy_id = f"7.root.store.{r.slug('/etc/paths')}"
        for held in (True, False):
            def respond(key, held=held):
                if r.CP in key:
                    return r.FakeResponse(exit=1)        # macOS cp -n exits 1 when the copy exists
                return r.FakeResponse(exit=0 if held or r.TEST not in key else 1)
            fake = r.FakeRunner(default=respond, run_dir=run, console=QuietConsole(), environ={})
            fake.phase = 7
            files = r.RootFiles(fake, run.run_id)
            with self.subTest(held=held):
                if held:
                    self.assertEqual(files.backup("/etc/paths"), f"{files.store}/{r.slug('/etc/paths')}")
                else:
                    with self.assertRaises(r.ActionFailed):
                        files.backup("/etc/paths")
                results = [e.get("result") for e in run.journal.entries() if e.get("action_id") == copy_id]
                self.assertEqual(results[-1], "ok" if held else "failed")


if __name__ == "__main__":
    unittest.main()

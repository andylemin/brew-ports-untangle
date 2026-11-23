"""`brew-ports env-cleanup` end to end against FakeRunner"""

import argparse
import functools
import os
import unittest
from unittest import mock

from brew_ports import envclean, runner as r, state
from brew_ports.context import Context
from brew_ports.model import Manager
from tests.unit.fixtures.envclean import builders as b
from tests.unit.helpers import TempDirTest
from tests.unit.test_env_paths import fixture

OLD_RUN = "20000101-000000-aaaaaa"


class EnvCleanupCommandTest(TempDirTest):
    """Tests of the `env-cleanup` command: its target, its survivors, its writes and its exit codes"""

    def setUp(self):
        super().setUp()
        self.sd = self.state_dir()
        self.sd.ensure()
        self.home = self.path("Users", "alice")
        self.etc = self.path("etc")
        os.makedirs(self.home)
        os.makedirs(self.etc)
        self.brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        self.ports = b.instance(self.tmp, Manager.PORTS, "opt/local")
        self.brew_prefix, self.ports_prefix = self.brew.prefix, self.ports.prefix
        self.runners = []
        self.ctx = self.context()            # replaced by the context of each cleanup()
        patcher = mock.patch("brew_ports.envclean.compute", functools.partial(envclean.compute, etc_dir=self.etc))
        patcher.start()
        self.addCleanup(patcher.stop)

    def rc(self, name, text):
        """Write a shell file in the home

        @param name  its name in the home
        @param text  its text
        @returns     its path
        """
        path = os.path.join(self.home, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def read(self, path):
        """Read a file's text

        @param path  the file
        @returns     its text
        """
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def make_runner(self, ctx, run_dir):
        """Return a fake runner for the command, whose syntax checks pass, and keep it in `runners`

        @param ctx      the command context, whose console and environment the runner takes
        @param run_dir  the run directory of the command
        @returns        the runner
        """
        fake = r.FakeRunner(default=b.syntax_responder(), console=ctx.console, environ=dict(ctx.environ),
                            run_dir=run_dir)
        self.runners.append(fake)
        return fake

    def context(self, **kw):
        """Return an `env-cleanup` command context for the user alice, with a quiet console and no terminal

        @param kw  the options that differ from the defaults: `target`, `apply`, `yes` or `dry_run`
        @returns   the context
        """
        values = {"command": "env-cleanup", "target": None, "apply": False, "yes": False, "dry_run": False}
        values.update(kw)
        return Context(argparse.Namespace(**values), b.QuietConsole(), self.sd, tty=False,
                       environ={"HOME": self.home, "USER": "alice", "PATH": "/usr/bin:/bin"})

    def cleanup(self, bundle, **kw):
        """Run `env-cleanup` over a scan that returns the bundle

        @param bundle  what the scan returns
        @param kw      the options that differ from the defaults
        @returns       the exit code
        """
        self.ctx = self.context(**kw)
        with mock.patch("brew_ports.scan.build", return_value=bundle):
            return envclean.cmd_env_cleanup(self.ctx, make_runner=self.make_runner)

    def completed_run(self, instances, journal=(), **kw):
        """Write an old run whose phase 5 completed, with a plan to Homebrew

        @param instances  the instances the plan records
        @param journal    the run's journal entries; empty for one `5.complete` record
        @param kw         further fields of the plan
        @returns          the run directory
        """
        plan = b.plan(self.brew, instances, run_id=OLD_RUN, **kw)
        entries = list(journal) or [{"phase": 5, "action_id": "5.complete", "result": "ok"}]
        return b.write_run(self.sd, OLD_RUN, plan, entries)

    def test_lines_of_a_deleted_prefix_go_by_its_record(self):
        gone = b.instance(self.tmp, Manager.BREW, "usr/local", roots=b.USR_LOCAL_ROOTS, exists=False)
        self.completed_run([self.brew, gone], journal=[
            {"phase": 6, "action_id": f"6.delete.{state.slug(gone.prefix)}", "result": "ok"},
            {"phase": 8, "action_id": "8.verify.login-shell.path"}], options={"remove_manager": gone.prefix})
        zprofile = self.rc(".zprofile", f'eval "$({gone.prefix}/bin/brew shellenv)"\n'
                                        f'eval "$({self.brew_prefix}/bin/brew shellenv)"\n')
        zshrc = self.rc(".zshrc", f'export PATH="{gone.prefix}/opt/coreutils/libexec/gnubin:$PATH"\n'
                                  f'export PATH="{gone.prefix}/go/bin:$PATH"\n')
        bundle = b.bundle([self.brew], [b.package(self.brew, "wget")], login_shell="/bin/zsh")
        self.assertEqual(self.cleanup(bundle, apply=True, yes=True), envclean.EXIT_OK)
        self.assertEqual(self.read(zprofile), f'eval "$({self.brew_prefix}/bin/brew shellenv)"\n')
        self.assertEqual(self.read(zshrc), f'export PATH="{gone.prefix}/go/bin:$PATH"\n')
        run_dir = self.runners[-1].run_dir
        dirty = self.sd.dirty()
        if dirty is None:
            self.fail("env-cleanup --apply left no dirty marker")
        self.assertEqual(dirty["run_id"], run_dir.run_id)
        self.assertEqual(dirty["command"], "env-cleanup")
        self.assertTrue(os.path.isfile(run_dir.backup_path(zshrc)))
        self.assertTrue(os.path.isfile(run_dir.sub("scan.json")))
        self.assertIn(f"{gone.prefix} counts as removed (gone: no instance is found there now)",
                      self.ctx.console.text)

    def test_a_kept_prefix_survives_with_its_lines(self):
        self.completed_run([self.brew, self.ports], journal=[
            {"phase": 6, "action_id": f"6.keep.{state.slug(self.ports_prefix)}", "result": "ok"},
            {"phase": 7, "action_id": "7.select.python"}])
        text = fixture("zprofile-macports.txt", PORTS=self.ports_prefix, BREW=self.brew_prefix)
        zprofile = self.rc(".zprofile", text)
        bundle = b.bundle([self.brew], [b.package(self.brew, "wget")], login_shell="/bin/zsh")
        self.assertEqual(self.cleanup(bundle, apply=True, yes=True), envclean.EXIT_OK)
        self.assertEqual(self.read(zprofile), text)
        self.assertIn(f"{self.ports_prefix} survives (kept by its phase 6 record)", self.ctx.console.text)
        self.assertIsNone(self.sd.dirty())

    def test_without_a_completed_run_the_target_is_required(self):
        b.write_run(self.sd, OLD_RUN, b.plan(self.brew, [self.brew]),
                    [{"phase": 3, "action_id": "3.install.bottled", "result": "ok"}])
        self.assertEqual(self.cleanup(b.bundle([self.brew])), envclean.EXIT_USAGE)
        self.assertIn("--target brew or --target ports", self.ctx.console.text)
        self.assertEqual(self.sd.run_ids(), [OLD_RUN])

    def test_an_explicit_target_without_a_run(self):
        zprofile = self.rc(".zprofile", f'eval "$({self.brew_prefix}/bin/brew shellenv)"\n'
                                        f"export PATH={self.ports_prefix}/bin:$PATH\n")
        bundle = b.bundle([self.brew, self.ports], [b.package(self.ports, "jq")], login_shell="/bin/zsh")
        self.assertEqual(self.cleanup(bundle, target="ports", apply=True, yes=True), envclean.EXIT_OK)
        self.assertEqual(self.read(zprofile), f"export PATH={self.ports_prefix}/bin:$PATH\n")

    def test_a_target_without_an_instance_exits_3(self):
        self.assertEqual(self.cleanup(b.bundle([self.brew]), target="ports"), envclean.EXIT_PREFLIGHT)

    def test_the_kept_installation_is_the_last_target_or_default(self):
        other = b.instance(self.tmp, Manager.BREW, "usr/local", roots=b.USR_LOCAL_ROOTS)
        kept = functools.partial(envclean.kept_prefix, self.sd, b.bundle([self.brew, other, self.ports]))
        self.assertEqual(kept("ports", "arm64", {}), self.ports_prefix)
        # Neither Homebrew lies at the default place, so only HOMEBREW_PREFIX names one.
        self.assertIsNone(kept("brew", "arm64", {}))
        self.assertEqual(kept("brew", "arm64", {"HOMEBREW_PREFIX": other.prefix}), other.prefix)
        run_dir = self.completed_run([self.brew, other, self.ports])
        self.assertEqual(kept("brew", "arm64", {"HOMEBREW_PREFIX": other.prefix}), self.brew_prefix)
        b.malform_plan(run_dir.sub("plan.json"))
        self.assertIsNone(kept("brew", "arm64", {"HOMEBREW_PREFIX": other.prefix}))

    def test_a_plan_with_a_malformed_field_exits_3(self):
        b.malform_plan(self.completed_run([self.brew, self.ports]).sub("plan.json"))
        self.assertEqual(self.cleanup(b.bundle([self.brew, self.ports])), envclean.EXIT_PREFLIGHT)
        self.assertIn("the latest run's plan.json cannot be read", self.ctx.console.text)

    def test_without_apply_or_a_yes_only_the_diff_prints(self):
        self.completed_run([self.brew, self.ports])
        zshrc = self.rc(".zshrc", f"export PATH={self.ports_prefix}/bin:$PATH\n")
        bundle = b.bundle([self.brew, self.ports], [b.package(self.brew, "wget")])
        for kw in ({}, {"apply": True, "dry_run": True}, {"apply": True}):
            with self.subTest(**kw):
                self.assertEqual(self.cleanup(bundle, **kw), envclean.EXIT_OK)
                self.assertEqual(self.read(zshrc), f"export PATH={self.ports_prefix}/bin:$PATH\n")
                self.assertIn(f"-export PATH={self.ports_prefix}/bin:$PATH", self.ctx.console.text)
                self.assertIsNone(self.sd.dirty())

    def test_a_failed_root_write_exits_4(self):
        self.completed_run([self.brew, self.ports])
        with open(os.path.join(self.etc, "paths"), "w", encoding="utf-8") as fh:
            fh.write(f"/usr/bin\n{self.ports_prefix}/bin\n")
        bundle = b.bundle([self.brew, self.ports], [b.package(self.brew, "wget")])
        self.assertEqual(self.cleanup(bundle, apply=True, yes=True), envclean.EXIT_ACTION)
        self.assertIn("files were not written", self.ctx.console.text)


if __name__ == "__main__":
    unittest.main()

"""The `brew` command builders: the argv, profile, timeout and failure policy of each, and their refusals"""

import unittest
from collections.abc import Callable
from typing import Any

from brew_ports import model, runner as r
from brew_ports.homebrew import actions as a
from tests.unit.helpers import TempDirTest, make_instance
from tests.unit.test_runner import QuietConsole

ARM = make_instance(prefix="/opt/homebrew", arch="arm64")
INTEL = make_instance(prefix="/usr/local", arch="x86_64", repository="/usr/local/Homebrew")
HEAD = [r.ARCH, "-arm64", "/opt/homebrew/bin/brew"]
INTEL_HEAD = [r.ARCH, "-x86_64", "/usr/local/bin/brew"]

PROBES: list[tuple[Callable[..., model.Action], tuple[Any, ...], list[str], int | None]] = [
    (a.config, (), ["config"], None),
    (a.cache, (), ["--cache"], None),
    (a.info_installed, (), ["info", "--json=v2", "--installed"], 600),
    (a.outdated, (), ["outdated", "--json=v2"], 600),
    (a.deps_installed, (), ["deps", "--formula", "--installed", "--for-each"], 600),
    (a.missing, (), ["missing"], 600),
    (a.doctor, (["check_deleted_formula", "check_for_stray_dylibs"],),
     ["doctor", "check_deleted_formula", "check_for_stray_dylibs"], None),
    (a.services_list, (), ["services", "list", "--json"], None),
    (a.bundle_dump, ("<run>/snapshot/brew-%opt%homebrew/Brewfile",),
     ["bundle", "dump", "--formula", "--cask", "--tap", "--no-restart",
      "--file=<run>/snapshot/brew-%opt%homebrew/Brewfile", "--force"], 600),
]


class ProbeBuilderTest(unittest.TestCase):
    """The read-only probes: their argv, policy, timeout and profile, and what an undrivable instance gets"""

    def test_every_probe_argv_and_policy(self):
        for build, args, tail, timeout in PROBES:
            with self.subTest(build=build.__name__):
                act = build(ARM, "arm64", "0.brew.%opt%homebrew.x", *args)
                self.assertEqual(act.argv, HEAD + tail)
                self.assertIs(act.on_failure, model.OnFailure.PROBE)
                self.assertTrue(act.read_only)
                self.assertEqual(act.timeout_s, timeout)
                self.assertEqual((act.env_profile, act.instance_prefix, act.sudo, act.kind),
                                 ("brew", "/opt/homebrew", False, "command"))

    def test_doctor_names_every_check_by_default(self):
        act = a.doctor(ARM, "arm64", "0.brew.doctor")
        self.assertEqual(act.argv, HEAD + ["doctor"] + list(a.DOCTOR_CHECKS))
        self.assertEqual(len(a.DOCTOR_CHECKS), 9)

    def test_only_config_takes_an_undrivable_instance(self):
        pending = make_instance(prefix="/opt/homebrew", drivable=False, usability=model.Usability.CANNOT_RUN)
        self.assertEqual(a.config(pending, "arm64", "0.c").argv, HEAD + ["config"])
        for build in (a.cache, a.info_installed, a.update):
            with self.assertRaises(ValueError):
                build(pending, "arm64", "0.x")
        with self.assertRaises(ValueError):
            a.install_formulae(pending, "arm64", "3.x", ["jq"])

    def test_missing_binary_builds_nothing(self):
        gone = make_instance(prefix="/usr/local", binary=None, drivable=False,
                             usability=model.Usability.MISSING_BINARY)
        with self.assertRaises(ValueError):
            a.config(gone, "arm64", "0.c")


class ArchTest(unittest.TestCase):
    """The `arch` prefix that an instance's architecture gives its commands on an arm64 or Intel host"""

    def test_intel_instance_on_arm64_runs_under_arch(self):
        self.assertEqual(a.info_installed(INTEL, "arm64", "0.i").argv,
                         INTEL_HEAD + ["info", "--json=v2", "--installed"])

    def test_no_arch_prefix_on_an_intel_host(self):
        self.assertEqual(a.update(INTEL, "x86_64", "r.u").argv, ["/usr/local/bin/brew", "update"])

    def test_unknown_arch_gets_no_prefix(self):
        inst = make_instance(prefix="/opt/homebrew", arch=None)
        self.assertEqual(a.cache(inst, "arm64", "0.c").argv, ["/opt/homebrew/bin/brew", "--cache"])


class MutationBuilderTest(unittest.TestCase):
    """The install, reinstall, upgrade, uninstall and single-name builders, and the manual line"""

    def test_install_formulae_is_a_split_batch(self):
        act = a.install_formulae(ARM, "arm64", "3.formulae.install", ["jq", "gnu-sed"])
        self.assertEqual(act.argv, HEAD + ["install", "--formula", "jq", "gnu-sed"])
        self.assertIs(act.on_failure, model.OnFailure.SPLIT)
        self.assertEqual(act.split_order, ["jq", "gnu-sed"])
        self.assertEqual(act.split_head, len(HEAD) + 2)
        self.assertEqual(r.split_argv(act, "gnu-sed"), HEAD + ["install", "--formula", "gnu-sed"])
        self.assertFalse(act.read_only)
        self.assertIsNone(act.timeout_s)

    def test_install_as_dependency(self):
        act = a.install_formulae(ARM, "arm64", "r.x", ["oniguruma"], as_dependency=True,
                                 on_failure=model.OnFailure.PROBE)
        self.assertEqual(act.argv, HEAD + ["install", "--formula", "--as-dependency", "oniguruma"])
        self.assertIs(act.on_failure, model.OnFailure.PROBE)
        self.assertEqual((act.split_order, act.split_head), ([], 0))

    def test_install_casks(self):
        act = a.install_casks(ARM, "arm64", "3.casks.install", ["firefox", "vlc"])
        self.assertEqual(act.argv, HEAD + ["install", "--cask", "firefox", "vlc"])
        self.assertEqual(r.split_argv(act, "vlc"), HEAD + ["install", "--cask", "vlc"])

    def test_adopt_cask_retries_with_force(self):
        act = a.adopt_cask(ARM, "arm64", "3.firefox.adopt", "firefox")
        self.assertEqual(act.argv, HEAD + ["install", "--cask", "--adopt", "firefox"])
        self.assertIs(act.on_failure, model.OnFailure.RETRY_WITH)
        self.assertEqual(act.retry_argv, HEAD + ["install", "--cask", "--force", "firefox"])

    def test_reinstall(self):
        one = a.reinstall(ARM, "arm64", "2.jq.reinstall", ["jq"])
        self.assertEqual(one.argv, HEAD + ["reinstall", "--formula", "jq"])
        self.assertIs(one.on_failure, model.OnFailure.STOP)
        batch = a.reinstall(ARM, "arm64", "3.formulae.reinstall", ["jq", "wget"])
        self.assertIs(batch.on_failure, model.OnFailure.SPLIT)
        self.assertEqual(batch.split_head, len(HEAD) + 2)
        cask = a.reinstall(ARM, "arm64", "2.vlc.reinstall", ["vlc"], kind="cask")
        self.assertEqual(cask.argv, HEAD + ["reinstall", "--cask", "vlc"])
        with self.assertRaises(ValueError):
            a.reinstall(ARM, "arm64", "x", ["jq"], kind="port")

    def test_upgrade_formulae(self):
        act = a.upgrade_formulae(ARM, "arm64", "3.formulae.upgrade", ["wget"])
        self.assertEqual(act.argv, HEAD + ["upgrade", "--formula", "wget"])
        self.assertIs(act.on_failure, model.OnFailure.SPLIT)

    def test_upgrade_casks_is_a_split_batch(self):
        act = a.upgrade_casks(ARM, "arm64", "3.upgrade.casks", ["firefox", "vlc"])
        self.assertEqual(act.argv, HEAD + ["upgrade", "--cask", "firefox", "vlc"])
        self.assertIs(act.on_failure, model.OnFailure.SPLIT)
        self.assertEqual(r.split_argv(act, "vlc"), HEAD + ["upgrade", "--cask", "vlc"])
        self.assertFalse(act.sudo)

    def test_unpin_names_casks_and_leaves_formulae_bare(self):
        formulae = a.unpin(ARM, "arm64", "3.unpin.formulae", ["node", "wget"])
        # No --formula: a Homebrew that pins formulae alone does not know the option.
        self.assertEqual(formulae.argv, HEAD + ["unpin", "node", "wget"])
        casks = a.unpin(ARM, "arm64", "3.unpin.casks", ["firefox"], casks=True)
        self.assertEqual(casks.argv, HEAD + ["unpin", "--cask", "firefox"])
        for act in (formulae, casks):
            self.assertIs(act.on_failure, model.OnFailure.PROBE)   # the upgrade that follows shows a pin that stayed
            self.assertEqual(act.env_profile, "brew")

    def test_a_command_for_the_user_is_typed_as_they_would_type_it(self):
        self.assertEqual(a.typed_line(ARM, ["upgrade", "--formula", "wget"], "arm64"),
                         "/opt/homebrew/bin/brew upgrade --formula wget")
        # Started without `arch`, an Intel Homebrew on Apple Silicon refuses to install into /usr/local.
        self.assertEqual(a.typed_line(INTEL, ["unpin", "node"], "arm64"), "arch -x86_64 /usr/local/bin/brew unpin node")
        self.assertEqual(a.typed_line(INTEL, ["unpin", "node"], "x86_64"), "/usr/local/bin/brew unpin node")

    def test_uninstall_splits_in_the_given_order(self):
        act = a.uninstall_formulae(ARM, "arm64", "5.uninstall.formulae", ["oniguruma", "jq"],
                                   split_order=["jq", "oniguruma"])
        self.assertEqual(act.argv, HEAD + ["uninstall", "--formula", "--force", "oniguruma", "jq"])
        self.assertEqual(act.split_order, ["jq", "oniguruma"])
        self.assertEqual(r.split_argv(act, "oniguruma"), HEAD + ["uninstall", "--formula", "--force", "oniguruma"])
        casks = a.uninstall_casks(ARM, "arm64", "5.uninstall.casks", ["vlc"])
        self.assertEqual(casks.argv, HEAD + ["uninstall", "--cask", "--force", "vlc"])
        self.assertEqual(casks.split_order, ["vlc"])
        with self.assertRaises(ValueError):
            a.uninstall_formulae(ARM, "arm64", "5.x", ["a", "b"], split_order=["a", "c"])

    def test_single_name_commands(self):
        cases = [
            (a.tab_installed_on_request(ARM, "arm64", "3.jq.tab", ["jq"]), ["tab", "--installed-on-request", "jq"]),
            (a.services_start(ARM, "arm64", "7.mysql.start", "mysql"), ["services", "start", "mysql"]),
            (a.tap(ARM, "arm64", "r.tap", "alice/tools"), ["tap", "alice/tools"]),
            (a.update(ARM, "arm64", "r.update"), ["update"]),
            (a.migrate(ARM, "arm64", "d.migrate", "act_runner"), ["migrate", "act_runner"]),
            (a.link(ARM, "arm64", "2.wget.link", "wget"), ["link", "wget"]),
            (a.bundle_install(ARM, "arm64", "r.bundle", "/tmp/Brewfile"),
             ["bundle", "install", "--no-upgrade", "--file=/tmp/Brewfile"]),
        ]
        for act, tail in cases:
            with self.subTest(tail=tail):
                self.assertEqual(act.argv, HEAD + tail)
                self.assertFalse(act.sudo)
                self.assertEqual(act.env_profile, "brew")
                self.assertFalse(act.read_only)
        self.assertIs(cases[1][0].on_failure, model.OnFailure.STOP)
        self.assertIs(cases[-1][0].on_failure, model.OnFailure.PROBE)
        started = a.services_start(ARM, "arm64", "r.start", "mysql", on_failure=model.OnFailure.PROBE)
        self.assertIs(started.on_failure, model.OnFailure.PROBE)

    def test_manual_line_is_never_run(self):
        act = a.manual(ARM, "5.vlc.manual", ["uninstall", "--cask", "vlc"], "run this on a terminal")
        self.assertTrue(act.manual)
        self.assertEqual(act.argv, ["/opt/homebrew/bin/brew", "uninstall", "--cask", "vlc"])
        fake = r.FakeRunner(console=QuietConsole(), environ={})
        with self.assertRaises(ValueError):
            fake.run(act)


class NameRuleTest(unittest.TestCase):
    """The refusal of empty name lists and of names that `brew` would read as options"""

    def test_empty_name_lists_are_refused(self):
        for build in (a.install_formulae, a.install_casks, a.upgrade_formulae, a.upgrade_casks, a.unpin,
                      a.uninstall_formulae, a.uninstall_casks, a.tab_installed_on_request, a.reinstall):
            with self.subTest(build=build.__name__):
                with self.assertRaises(ValueError):
                    build(ARM, "arm64", "3.x", [])
        with self.assertRaises(ValueError):
            a.doctor(ARM, "arm64", "0.d", [])

    def test_option_shaped_names_are_refused(self):
        with self.assertRaises(ValueError):
            a.uninstall_formulae(ARM, "arm64", "5.x", ["--ignore-dependencies"])
        with self.assertRaises(ValueError):
            a.services_start(ARM, "arm64", "7.x", "-v")


class RunnerIntegrationTest(TempDirTest):
    """A split batch and the `brew` profile, run through the fake runner"""

    def test_split_batch_retries_each_name(self):
        run = self.state_dir().new_run()
        argv = tuple(HEAD + ["install", "--formula"])
        fake = r.FakeRunner(responses={argv + ("jq", "gnu-sed"): r.FakeResponse(exit=1),
                                       argv + ("jq",): r.FakeResponse(exit=0),
                                       argv + ("gnu-sed",): r.FakeResponse(exit=1)},
                            run_dir=run, console=QuietConsole(), environ={"HOME": self.tmp})
        fake.phase = 3
        res = fake.run(a.install_formulae(ARM, "arm64", "3.formulae.install", ["jq", "gnu-sed"]))
        self.assertEqual(res.failed, ["gnu-sed"])
        self.assertEqual(run.journal.result(3, "3.formulae.install"), "failed")

    def test_brew_profile_reaches_the_child(self):
        act = a.update(ARM, "arm64", "r.update")
        env = r.FakeRunner(console=QuietConsole(), environ={"HOME": "/h", "HOMEBREW_DEVELOPER": "1"}).env_for(act)
        self.assertEqual(env["HOMEBREW_NO_SUDO"], "1")
        self.assertNotIn("HOMEBREW_DEVELOPER", env)
        self.assertTrue(env["PATH"].startswith("/opt/homebrew/bin:/opt/homebrew/sbin:"))


if __name__ == "__main__":
    unittest.main()

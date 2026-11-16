"""Locating Homebrew instances: spellings, `/usr/local`, the Ruby gate, the target choice and `brew.env`"""

import os
import unittest
from unittest import mock

from brew_ports import model, runner as r, system
from brew_ports.homebrew import locate
from tests.unit.helpers import TempDirTest, make_instance
from tests.unit.test_homebrew_support import fake, symlink, write

RUBY = locate.PORTABLE_RUBY


class LocateCase(TempDirTest):
    """A temporary root that stands in for `/opt/homebrew`, `/usr/local` and the system `brew.env`"""

    def setUp(self):
        super().setUp()
        self.opt = self.path("opt", "homebrew")
        self.usr_local = self.path("usr", "local")
        self.home = self.path("Users", "alice")
        for name, value in (("ARM64_PREFIX", self.opt), ("USR_LOCAL", self.usr_local),
                            ("SYSTEM_BREW_ENV", self.path("etc", "homebrew", "brew.env"))):
            patcher = mock.patch.object(locate, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def env(self, **extra):
        """Return the tests' environment: `HOME` and a system PATH, with further variables

        @param extra  further variables, which replace the defaults
        @returns      the environment
        """
        env = {"HOME": self.home, "PATH": "/usr/bin:/bin"}
        env.update(extra)
        return env

    def make_opt(self, ruby=True):
        """Make an `/opt/homebrew` prefix with its `bin/brew` and its repository

        @param ruby  give the repository its portable Ruby
        @returns     the prefix
        """
        write(os.path.join(self.opt, "bin", "brew"), "#!/bin/sh\n", 0o755)
        os.makedirs(os.path.join(self.opt, "Library", "Homebrew"), exist_ok=True)
        if ruby:
            write(os.path.join(self.opt, RUBY), "", 0o755)
        return self.opt

    def make_usr_local(self, brew=True, ruby=True):
        """Make a `/usr/local` prefix with a Cellar and its repository in `/usr/local/Homebrew`

        @param brew  give the prefix a `bin/brew`, a link to the repository's
        @param ruby  give the repository its portable Ruby
        @returns     the prefix
        """
        repo = os.path.join(self.usr_local, "Homebrew")
        os.makedirs(os.path.join(repo, "Library", "Homebrew"), exist_ok=True)
        os.makedirs(os.path.join(self.usr_local, "Cellar"), exist_ok=True)
        if brew:
            write(os.path.join(repo, "bin", "brew"), "#!/bin/sh\n", 0o755)
            symlink(os.path.join(self.usr_local, "bin", "brew"), "../Homebrew/bin/brew")
        if ruby:
            write(os.path.join(repo, RUBY), "", 0o755)
        return self.usr_local

    def brew_cache(self):
        """Return the download cache that `brew --cache` prints in the canned answers

        @returns  the path
        """
        return self.path("cache-from-brew")

    def ok_responses(self, prefix_key, ruby_key, arch_word="arm64", arch_prefix=("/usr/bin/arch", "-arm64"),
                     version="7.0.11"):
        """Return the canned answers of the four probes of a usable instance

        @param prefix_key   the prefix, the temporary root spelled `<tmp>`
        @param ruby_key     the portable Ruby, spelled the same way
        @param arch_word    what `lipo -archs` prints
        @param arch_prefix  the `arch` words the probes run under
        @param version      the `HOMEBREW_VERSION` that `brew config` prints
        @returns            the responses by argv
        """
        brew = arch_prefix + (prefix_key + "/bin/brew",)
        return {
            (locate.LIPO, "-archs", ruby_key): r.FakeResponse(stdout=arch_word + "\n"),
            arch_prefix + (ruby_key, "-e", "exit 0"): r.FakeResponse(),
            brew + ("config",): r.FakeResponse(stdout=f"HOMEBREW_VERSION: {version}\nORIGIN: x\n"),
            brew + ("--cache",): r.FakeResponse(stdout=f"Warning: something\n{self.brew_cache()}\n"),
        }


class IdentityMergeTest(LocateCase):
    """One instance per prefix identity, whatever spellings the candidates use"""

    def test_case_and_data_volume_spellings_are_one(self):
        self.make_opt()
        # A case variant on a case-insensitive volume, such as the default APFS one, has the same
        # identity; on a case-sensitive volume a symlink gives it that identity.
        if not os.path.lexists(self.path("opt", "Homebrew")):
            symlink(self.path("opt", "Homebrew"), "homebrew")
        symlink(self.path("System", "Volumes", "Data", "opt"), os.path.join(self.tmp, "opt"))
        data_spelling = self.path("System", "Volumes", "Data", "opt", "homebrew")
        env = self.env(PATH=self.path("opt", "Homebrew", "bin") + ":/usr/bin", HOMEBREW_PREFIX=data_spelling)
        runner = fake(self.tmp, self.ok_responses("<tmp>/opt/homebrew", "<tmp>/opt/homebrew/" + RUBY), env)
        found = locate.find_instances(runner, env, "arm64")
        self.assertEqual(len(found), 1)
        inst = found[0]
        self.assertEqual(inst.prefix, self.opt)
        self.assertEqual(inst.identity, system.identity(self.opt))
        self.assertEqual(inst.spellings, (self.opt, self.path("opt", "Homebrew"), data_spelling))
        self.assertIs(inst.usability, model.Usability.USABLE)
        self.assertTrue(inst.drivable)
        self.assertEqual(inst.version, "7.0.11")
        self.assertEqual(inst.arch, "arm64")
        self.assertEqual(inst.repository, self.opt)
        self.assertEqual(inst.cache_dir, self.brew_cache())
        self.assertEqual(inst.owned_roots, (self.opt,))

    def test_two_prefixes_in_search_order(self):
        self.make_opt()
        self.make_usr_local()
        env = self.env()
        responses = self.ok_responses("<tmp>/opt/homebrew", "<tmp>/opt/homebrew/" + RUBY)
        responses.update(self.ok_responses("<tmp>/usr/local", "<tmp>/usr/local/Homebrew/" + RUBY, "x86_64",
                                           ("/usr/bin/arch", "-x86_64"), "6.0.0"))
        found = locate.find_instances(fake(self.tmp, responses, env), env, "arm64")
        self.assertEqual([i.prefix for i in found], [self.opt, self.usr_local])
        intel = found[1]
        self.assertEqual((intel.arch, intel.version, intel.repository),
                         ("x86_64", "6.0.0", os.path.join(self.usr_local, "Homebrew")))

    def test_a_brew_wrapper_on_path_makes_no_instance(self):
        write(self.path("Users", "alice", "bin", "brew"), "#!/bin/sh\nexec /opt/homebrew/bin/brew \"$@\"\n", 0o755)
        env = self.env(PATH=self.path("Users", "alice", "bin") + ":relative:/usr/bin")
        self.assertEqual(locate.find_instances(fake(self.tmp, {}, env), env, "arm64"), [])

    def test_group_records_the_realpath(self):
        self.make_opt()
        symlink(self.path("link"), self.opt)
        groups = locate.group_by_identity([self.path("link"), self.opt, self.path("missing")])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][1], [self.path("link"), self.opt])


class UsrLocalTest(LocateCase):
    """A `/usr/local` prefix: the subtrees Homebrew owns there, and a Cellar without a `brew`"""

    def test_usr_local_owns_only_homebrew_subtrees(self):
        self.make_usr_local(ruby=False)
        inst = locate.find_instances(fake(self.tmp, {}, self.env()), self.env(), "x86_64")[0]

        def sub(*parts):
            return os.path.join(self.usr_local, *parts)
        self.assertEqual(inst.owned_roots, (sub("Cellar"), sub("Caskroom"), sub("Homebrew"), sub("opt"),
                                            sub("var", "homebrew")))
        self.assertEqual(inst.repository, sub("Homebrew"))
        keg_bin = write(sub("Cellar", "wget", "1.25.0", "bin", "wget"), "", 0o755)
        symlink(sub("bin", "wget"), "../Cellar/wget/1.25.0/bin/wget")
        write(sub("go", "bin", "go"), "", 0o755)
        self.assertTrue(locate.owns_path(inst, keg_bin))
        self.assertTrue(locate.owns_path(inst, sub("bin", "wget")))
        self.assertFalse(locate.owns_path(inst, sub("go", "bin", "go")))
        self.assertFalse(locate.owns_path(inst, sub("bin")))
        self.assertFalse(locate.owns_path(inst, sub("Caskroom", "not-yet-created")))

    def test_cellar_without_brew_is_missing_binary(self):
        os.makedirs(os.path.join(self.usr_local, "Cellar", "wget", "1.0"))
        runner = fake(self.tmp, {}, self.env())
        found = locate.find_instances(runner, self.env(), "arm64")
        self.assertEqual(len(found), 1)
        inst = found[0]
        self.assertIs(inst.usability, model.Usability.MISSING_BINARY)
        self.assertFalse(inst.drivable)
        self.assertIsNone(inst.binary)
        self.assertEqual(inst.cache_dir, self.path("Users", "alice", "Library", "Caches", "Homebrew"))
        self.assertEqual(runner.calls, [])

    def test_dedicated_prefix_owns_itself(self):
        self.make_opt()
        self.assertEqual(locate.owned_roots(self.opt), (self.opt,))


class RubyGateTest(LocateCase):
    """The portable Ruby gate before any `brew` runs, the probe order and the probe parsers"""

    def brew_calls(self, runner):
        """Return the calls of a runner that ran a `brew` binary

        @param runner  the FakeRunner
        @returns       the calls, in their order
        """
        return [c for c in runner.calls if any(part.endswith("/bin/brew") for part in c)]

    def test_missing_ruby_is_cannot_run_without_any_brew(self):
        self.make_opt(ruby=False)
        runner = fake(self.tmp, {}, self.env())
        inst = locate.find_instances(runner, self.env(), "arm64")[0]
        self.assertIs(inst.usability, model.Usability.CANNOT_RUN)
        self.assertIn("portable Ruby is missing", inst.usability_detail or "")
        self.assertIsNone(inst.arch)
        self.assertEqual(runner.calls, [])

    def test_failing_ruby_is_cannot_run_with_its_error(self):
        self.make_opt()
        ruby = "<tmp>/opt/homebrew/" + RUBY
        responses = self.ok_responses("<tmp>/opt/homebrew", ruby, "x86_64", ("/usr/bin/arch", "-x86_64"))
        responses[("/usr/bin/arch", "-x86_64", ruby, "-e", "exit 0")] = r.FakeResponse(
            exit=1, stderr=f"arch: posix_spawnp: {ruby}: Bad CPU type in executable\n")
        runner = fake(self.tmp, responses, self.env())
        inst = locate.find_instances(runner, self.env(), "arm64")[0]
        self.assertIs(inst.usability, model.Usability.CANNOT_RUN)
        self.assertIn("Bad CPU type in executable", inst.usability_detail or "")
        self.assertEqual(inst.arch, "x86_64")
        self.assertEqual(self.brew_calls(runner), [])
        self.assertEqual(runner.calls[0], (locate.LIPO, "-archs", ruby))

    def test_failing_config_skips_the_cache_probe(self):
        self.make_opt()
        ruby = "<tmp>/opt/homebrew/" + RUBY
        responses = self.ok_responses("<tmp>/opt/homebrew", ruby)
        responses[("/usr/bin/arch", "-arm64", "<tmp>/opt/homebrew/bin/brew", "config")] = r.FakeResponse(
            exit=1, stderr="Error: Homebrew's portable Ruby is outdated\n")
        runner = fake(self.tmp, responses, self.env())
        inst = locate.find_instances(runner, self.env(), "arm64")[0]
        self.assertIs(inst.usability, model.Usability.CANNOT_RUN)
        self.assertIn("brew config failed with exit 1", inst.usability_detail or "")
        self.assertNotIn(("/usr/bin/arch", "-arm64", "<tmp>/opt/homebrew/bin/brew", "--cache"), runner.calls)
        self.assertIsNone(inst.version)

    def test_probe_order_is_lipo_ruby_config_cache(self):
        self.make_opt()
        ruby = "<tmp>/opt/homebrew/" + RUBY
        runner = fake(self.tmp, self.ok_responses("<tmp>/opt/homebrew", ruby, "x86_64 arm64"), self.env())
        inst = locate.find_instances(runner, self.env(), "arm64")[0]
        self.assertEqual(inst.arch, "arm64")
        self.assertEqual([c[-1] for c in runner.calls], [ruby, "exit 0", "config", "--cache"])

    def test_intel_host_runs_without_arch(self):
        self.make_usr_local()
        ruby = "<tmp>/usr/local/Homebrew/" + RUBY
        runner = fake(self.tmp, self.ok_responses("<tmp>/usr/local", ruby, "x86_64", ()), self.env(),
                      host_arch="x86_64")
        inst = locate.find_instances(runner, self.env(), "x86_64")[0]
        self.assertTrue(inst.drivable)
        self.assertIn((ruby, "-e", "exit 0"), runner.calls)

    def test_parse_archs(self):
        self.assertEqual(locate.parse_archs("x86_64 arm64\n", "arm64"), "arm64")
        self.assertEqual(locate.parse_archs("x86_64 arm64e\n", "x86_64"), "x86_64")
        self.assertEqual(locate.parse_archs("arm64e\n", "x86_64"), "arm64")
        self.assertIsNone(locate.parse_archs("", "arm64"))

    def test_config_value(self):
        text = "HOMEBREW_VERSION: 7.0.11\nHOMEBREW_PREFIX: /opt/homebrew\nCPU: octa-core 64-bit\n"
        self.assertEqual(locate.config_value(text, "HOMEBREW_PREFIX"), "/opt/homebrew")
        self.assertIsNone(locate.config_value(text, "HOMEBREW_REPOSITORY"))


class TargetChoiceTest(TempDirTest):
    """The Homebrew target of a plan: `--target-prefix`, the host's default prefix, then `HOMEBREW_PREFIX`"""

    def setUp(self):
        super().setUp()
        self.opt = self.path("opt", "homebrew")
        self.usr = self.path("usr", "local")
        self.custom = self.path("custom", "brew")
        for path in (self.opt, self.usr, self.custom):
            os.makedirs(path)
        for name, value in (("ARM64_PREFIX", self.opt), ("USR_LOCAL", self.usr)):
            patcher = mock.patch.object(locate, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def inst(self, prefix, drivable=True, **kw):
        """Return a Homebrew instance at a prefix, usable when it is drivable

        @param prefix    the prefix
        @param drivable  whether the instance is drivable, which decides its usability
        @param kw        further `Instance` fields
        @returns         the instance
        """
        return make_instance(prefix=prefix, identity=system.identity(prefix) or (0, 0), drivable=drivable,
                             usability=model.Usability.USABLE if drivable else model.Usability.CANNOT_RUN, **kw)

    def test_target_prefix_comes_first(self):
        opt, usr = self.inst(self.opt), self.inst(self.usr)
        self.assertIs(locate.choose_target([opt, usr], "arm64", self.usr, {}), usr)
        symlink(self.path("alias"), self.usr)
        self.assertIs(locate.choose_target([opt, usr], "arm64", self.path("alias"), {}), usr)
        self.assertIsNone(locate.choose_target([opt, usr], "arm64", self.custom, {}))

    def test_gone_target_prefix_matches_a_spelling(self):
        gone = make_instance(prefix="/nonexistent/brew", identity=(7, 7), spellings=("/nonexistent/brew",))
        self.assertIs(locate.choose_target([gone], "arm64", "/System/Volumes/Data/nonexistent/brew/", {}), gone)

    def test_host_default_prefix_then_homebrew_prefix(self):
        opt, usr, custom = self.inst(self.opt), self.inst(self.usr), self.inst(self.custom)
        env = {"HOMEBREW_PREFIX": self.custom}
        self.assertIs(locate.choose_target([usr, opt, custom], "arm64", None, env), opt)
        self.assertIs(locate.choose_target([opt, usr, custom], "x86_64", None, env), usr)
        self.assertIs(locate.choose_target([usr, custom], "arm64", None, env), custom)
        undrivable_opt = self.inst(self.opt, drivable=False)
        self.assertIs(locate.choose_target([undrivable_opt, custom], "arm64", None, env), custom)
        self.assertIsNone(locate.choose_target([undrivable_opt, usr], "arm64", None, {}))
        self.assertIsNone(locate.choose_target([], "arm64", None, env))

    def test_macports_is_never_a_homebrew_target(self):
        ports = make_instance(manager=model.Manager.PORTS, prefix=self.opt, identity=system.identity(self.opt))
        self.assertIsNone(locate.choose_target([ports], "arm64", None, {}))


class BrewEnvTest(TempDirTest):
    """The `brew.env` lines that `bin/brew` exports: its parsing, the load order and the system priority"""

    def setUp(self):
        super().setUp()
        self.system_file = self.path("etc", "homebrew", "brew.env")
        patcher = mock.patch.object(locate, "SYSTEM_BREW_ENV", self.system_file)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.prefix = self.path("opt", "homebrew")

    def test_lines_follow_bin_brew_parsing(self):
        prefix_file = write(os.path.join(self.prefix, "etc", "homebrew", "brew.env"),
                            "# comment HOMEBREW_NO_SUDO=0\n"
                            "\tHOMEBREW_NO_AUTOREMOVE=\n"
                            "HOMEBREW_PREFIX=/elsewhere\n"
                            "HOMEBREW_REPOSITORY\n"
                            "https_proxy=http://proxy.example:3128\n"
                            "HTTPS_PROXY=http://upper.example\n"
                            "SUDO_ASKPASS=/usr/local/bin/askpass\n"
                            "HOMEBREW_CASK_OPTS=\"--appdir=~/Apps\"\n"
                            "HOMEBREW_EXPERIMENTAL_RUST_FRONTEND=1\n"
                            "HOMEBREW_BAD NAME=1\n"
                            "HOMEBREW_DEBUG=1")
        lines = locate.brew_env_lines(self.prefix, {"HOME": self.path("home")})
        self.assertEqual([(l.name, l.value, l.lineno) for l in lines], [
            ("HOMEBREW_NO_AUTOREMOVE", "", 2), ("https_proxy", "http://proxy.example:3128", 5),
            ("SUDO_ASKPASS", "/usr/local/bin/askpass", 7), ("HOMEBREW_CASK_OPTS", "\"--appdir=~/Apps\"", 8)])
        self.assertTrue(all(l.path == prefix_file for l in lines))

    def test_load_order_and_system_priority(self):
        write(self.system_file, "HOMEBREW_NO_ANALYTICS=1\nHOMEBREW_SYSTEM_ENV_TAKES_PRIORITY=1\n")
        write(os.path.join(self.prefix, "etc", "homebrew", "brew.env"), "HOMEBREW_NO_ANALYTICS=0\n")
        user = write(self.path("xdg", "homebrew", "brew.env"), "HOMEBREW_NO_ANALYTICS=2\n")
        env = {"HOME": self.path("home"), "XDG_CONFIG_HOME": self.path("xdg")}
        lines = locate.brew_env_lines(self.prefix, env)
        self.assertEqual([l.path for l in lines], [self.system_file, self.system_file,
                                                   os.path.join(self.prefix, "etc", "homebrew", "brew.env"),
                                                   user, self.system_file, self.system_file])
        self.assertEqual(locate.effective("HOMEBREW_NO_ANALYTICS", env, lines), "1")
        self.assertEqual(locate.effective("HOMEBREW_TEMP", {"HOMEBREW_TEMP": "/t"}, lines), "/t")

    def test_user_file_defaults_to_dot_homebrew(self):
        files = locate.brew_env_files(self.prefix, {"HOME": "/Users/alice"})
        self.assertEqual(files[2], "/Users/alice/.homebrew/brew.env")


class FailureTextTest(unittest.TestCase):
    """The error text that a failed or timed-out probe leaves on the instance"""

    def test_failure_text(self):
        res = r.Result("x", 1, None, None)
        self.assertEqual(locate.failure_text(res, "brew config"), "brew config failed with exit 1")
        res.timed_out = True
        self.assertEqual(locate.failure_text(res, "brew info"), "brew info timed out")


if __name__ == "__main__":
    unittest.main()

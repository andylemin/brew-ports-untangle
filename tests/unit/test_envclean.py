"""Environment cleanup: the survivor set, the environment edits and `apply`"""

import os
import unittest

from brew_ports import envclean, runner as r, state, system
from brew_ports.env import shell as env_shell
from brew_ports.model import Manager
from tests.unit.fixtures.envclean import builders as b
from tests.unit.helpers import TempDirTest, make_instance
from tests.unit.test_env_paths import fixture


class CleanupTest(TempDirTest):
    """The base of the cleanup tests: a home, an `/etc` with `paths.d`, and a Homebrew and a MacPorts instance"""

    def setUp(self):
        super().setUp()
        self.home = self.path("Users", "alice")
        self.etc = self.path("etc")
        os.makedirs(self.home)
        os.makedirs(os.path.join(self.etc, "paths.d"))
        self.brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        self.ports = b.instance(self.tmp, Manager.PORTS, "opt/local")
        self.brew_prefix, self.ports_prefix = self.brew.prefix, self.ports.prefix

    def rc(self, name, text):
        """Write a shell file below the home

        @param name  its path below the home, with `/` separators
        @param text  its text
        @returns     its path
        """
        path = os.path.join(self.home, *name.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def etc_file(self, name, text):
        """Write a file below the test's `/etc`

        @param name  its path below `/etc`, with `/` separators
        @param text  its text
        @returns     its path
        """
        path = os.path.join(self.etc, *name.split("/"))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def survivors(self, surviving, removed, primary=None, instances=None):
        """Return a survivor set made by hand, with no reasons

        @param surviving  the instances that survive
        @param removed    the instances that count as removed
        @param primary    the primary survivor, or None
        @param instances  the instances tested; None for the Homebrew and the MacPorts one
        @returns          the survivor set
        """
        return envclean.Survivors(list(instances or [self.brew, self.ports]), [i.prefix for i in surviving],
                                  [i.prefix for i in removed], primary.prefix if primary else None)

    def compute(self, surv, login=None, gui=None, uid=None, environ=None):
        """Compute the environment edits over a scan of the survivor set's instances

        @param surv     the survivor set
        @param login    the login shell, or None
        @param gui      the entries of the GUI PATH, or None
        @param uid      whose rc files the tool may write; None for the user's
        @param environ  the environment; None for the home and a PATH of `/usr/bin:/bin`
        @returns        the edits
        """
        bundle = b.bundle(surv.instances, login_shell=login, gui=gui)
        env = environ or {"HOME": self.home, "PATH": "/usr/bin:/bin"}
        return envclean.compute(bundle, surv, self.home, env, etc_dir=self.etc, uid=uid)

    def ports_removed(self, **kw):
        """Compute the edits when Homebrew survives as the primary survivor and MacPorts counts as removed

        @param kw  further options of `compute`
        @returns   the edits
        """
        return self.compute(self.survivors([self.brew], [self.ports], self.brew), **kw)

    @staticmethod
    def edit(edits, path):
        """Return the edit of one file, failing the test when there is none

        @param edits  the edits
        @param path   the file
        @returns      its first edit
        """
        found = [e for e in edits if e.path == path]
        if not found:
            raise AssertionError(f"no edit for {path} among {[e.path for e in edits]}")
        return found[0]

    def run_dir(self):
        """Return a run directory in the test's state directory

        @returns  the run directory
        """
        return state.StateDir(self.path("state")).new_run()


class SurvivorsTest(CleanupTest):
    """Tests of the survivor set: the target, packages, recorded instances, keeps and the primary survivor"""

    def test_the_target_packages_and_empty_instances_decide(self):
        other = b.instance(self.tmp, Manager.BREW, "usr/local", roots=b.USR_LOCAL_ROOTS)
        bundle = b.bundle([self.brew, self.ports, other], [b.package(other, "wget")])
        surv = envclean.survivors(bundle, None, target_prefix=self.brew_prefix)
        self.assertEqual(surv.surviving, [self.brew_prefix, other.prefix])
        self.assertEqual(surv.removed, [self.ports_prefix])
        self.assertEqual(surv.primary, self.brew_prefix)
        self.assertEqual(surv.reasons[self.ports_prefix], "holds no package")
        self.assertEqual(surv.reasons[other.prefix], "holds 1 package")

    def test_a_recorded_only_instance_counts_as_removed(self):
        gone = b.instance(self.tmp, Manager.BREW, "usr/local", roots=b.USR_LOCAL_ROOTS, exists=False,
                          spellings=(self.path("usr", "local"), "/System/Volumes/Data" + self.path("usr", "local")))
        plan = b.plan(self.brew, [self.brew, gone])
        surv = envclean.survivors(b.bundle([self.brew]), plan)
        self.assertEqual((surv.surviving, surv.removed), ([self.brew_prefix], [gone.prefix]))
        self.assertIs(surv.instance(gone.prefix), gone)
        self.assertEqual(surv.reasons[gone.prefix], "gone: no instance is found there now")

    def test_the_plan_spellings_join_a_fresh_instance(self):
        alias = self.path("alias-homebrew")
        recorded = make_instance(Manager.BREW, self.brew_prefix, identity=self.brew.identity,
                                 spellings=(self.brew_prefix, alias), owned_roots=(self.brew_prefix,))
        tested = envclean.tested_instances([self.brew], [recorded])
        self.assertEqual(len(tested), 1)
        self.assertEqual(tested[0].spellings, (self.brew_prefix, alias))

    def test_an_unknown_registry_is_never_known_to_be_empty(self):
        damaged = b.instance(self.tmp, Manager.PORTS, "opt/damaged", inventory_known=False)
        surv = envclean.survivors(b.bundle([self.brew, damaged]), None, target_prefix=self.brew_prefix)
        self.assertIn(damaged.prefix, surv.surviving)
        self.assertIn("ports-damaged-registry", surv.reasons[damaged.prefix])

    @unittest.skipIf(os.geteuid() == 0, "root lists any directory")
    def test_an_unlistable_cellar_is_never_empty(self):
        other = b.instance(self.tmp, Manager.BREW, "opt/other-brew")
        cellar = os.path.join(other.prefix, "Cellar")
        os.makedirs(cellar)
        os.chmod(cellar, 0)
        self.addCleanup(os.chmod, cellar, 0o755)
        surv = envclean.survivors(b.bundle([self.brew, other]), None, target_prefix=self.brew_prefix)
        self.assertIn(other.prefix, surv.surviving)
        self.assertIn("cannot be listed", surv.reasons[other.prefix])

    def test_a_keep_record_holds_until_phase_6_acts_again(self):
        other = b.instance(self.tmp, Manager.PORTS, "opt/other", exists=False)
        run_dir = self.run_dir()
        for entry in ({"phase": 6, "action_id": f"6.archive.{state.slug(self.ports_prefix)}%var%db"},
                      {"phase": 6, "action_id": f"6.keep.{state.slug(self.ports_prefix)}", "result": "ok"},
                      {"phase": 6, "action_id": f"6.keep.{other.prefix}", "result": "ok"},
                      {"phase": 6, "action_id": f"6.delete.{state.slug(other.prefix)}", "result": "ok"},
                      {"phase": 6, "action_id": "6.root.store.%etc%paths.d%macports"}):
            run_dir.journal.append(entry)
        self.assertEqual(envclean.phase6_keeps(run_dir.journal), [self.ports_prefix])
        plan = b.plan(self.brew, [self.brew, self.ports, other])
        surv = envclean.survivors(b.bundle([self.brew, self.ports]), plan, run_dir.journal)
        self.assertEqual(surv.surviving, [self.brew_prefix, self.ports_prefix])
        self.assertEqual(surv.removed, [other.prefix])
        self.assertEqual(surv.reasons[self.ports_prefix], "kept by its phase 6 record")

    def test_the_source_stays_primary_after_an_only_run(self):
        second = b.instance(self.tmp, Manager.BREW, "usr/local", roots=b.USR_LOCAL_ROOTS)
        packages = [b.package(self.ports, "jq"), b.package(second, "wget")]
        plan = b.plan(self.brew, [self.brew, self.ports, second], options={"only": "zstd"})
        live = [("/usr/bin", None), (os.path.join(second.prefix, "bin"), second.prefix),
                (os.path.join(self.ports_prefix, "bin"), self.ports_prefix)]
        surv = envclean.survivors(b.bundle([self.brew, self.ports, second], packages, live_path=live), plan)
        self.assertEqual(surv.primary, second.prefix)
        plan.options["only"] = ""
        self.assertEqual(envclean.survivors(b.bundle([self.brew, self.ports, second], packages), plan).primary,
                         self.brew_prefix)

    def test_phase_completed(self):
        run_dir = self.run_dir()
        self.assertFalse(envclean.phase_completed(run_dir, 5))
        run_dir.journal.append({"phase": 5, "action_id": "5.uninstall.formulae", "result": "ok"})
        self.assertFalse(envclean.phase_completed(run_dir, 5))
        run_dir.journal.append({"phase": 5, "action_id": "5.complete", "result": "ok"})
        self.assertTrue(envclean.phase_completed(run_dir, 5))
        later = self.run_dir()
        later.journal.append({"phase": 7, "action_id": "7.write.%x"})
        self.assertTrue(envclean.phase_completed(later, 5))
        self.assertFalse(envclean.phase_completed(later, 7))


class PathLinesTest(CleanupTest):
    """Tests of the PATH, MANPATH, DYLD and build lines that name a removed prefix"""

    def test_whole_lines_go_and_user_entries_stay(self):
        path = self.rc(".bash_profile", "\n".join([
            f'export PATH="{self.ports_prefix}/bin:$HOME/.cargo/bin:/usr/local/bin:{self.ports_prefix}/sbin:$PATH"',
            f"export PATH={self.ports_prefix}/bin:{self.ports_prefix}/sbin:$PATH",
            f"export MANPATH={self.ports_prefix}/share/man:$MANPATH",
            f"export PATH={self.brew_prefix}/bin:$PATH",
        ]) + "\n")
        edit = self.edit(self.ports_removed(), path)
        self.assertEqual(edit.new_text, 'export PATH="$HOME/.cargo/bin:/usr/local/bin:$PATH"\n'
                                        f"export PATH={self.brew_prefix}/bin:$PATH\n")
        self.assertEqual([op.split(":")[0] for op in edit.ops],
                         ["path entries, line 1", "manager setup, line 2", "manager setup, line 3"])
        self.assertIn(f"-export MANPATH={self.ports_prefix}/share/man:$MANPATH", edit.diff)
        self.assertIsNone(edit.manual)

    def test_word_lists_of_zsh_csh_and_fish(self):
        zshrc = self.rc(".zshrc", f"path=({self.ports_prefix}/bin $HOME/bin $path)\n"
                                  f"path=({self.ports_prefix}/bin $path)\n")
        tcshrc = self.rc(".tcshrc", f"set path = ( {self.ports_prefix}/bin $HOME/bin $path )\n"
                                    f"setenv PATH {self.ports_prefix}/bin:$PATH\n")
        fish = self.rc(".config/fish/config.fish", f"fish_add_path {self.ports_prefix}/bin /x/bin\n"
                                                   f"set -gx PATH {self.ports_prefix}/sbin $PATH\n")
        edits = self.ports_removed()
        self.assertEqual(self.edit(edits, zshrc).new_text, "path=($HOME/bin $path)\n")
        self.assertEqual(self.edit(edits, tcshrc).new_text, "set path = ( $HOME/bin $path )\n")
        self.assertEqual(self.edit(edits, fish).new_text, "fish_add_path /x/bin\n")

    def test_drop_entries(self):
        self.assertEqual(envclean.drop_entries('export PATH="/a:/b:$PATH"', ["/a"]), 'export PATH="/b:$PATH"')
        self.assertEqual(envclean.drop_entries('export PATH="$PATH:/a"  # mine', ["/a"]), 'export PATH="$PATH"  # mine')
        self.assertEqual(envclean.drop_entries("export PATH=/a/bin:/a:/a/bin2:$PATH", ["/a"]),
                         "export PATH=/a/bin:/a/bin2:$PATH")
        self.assertEqual(envclean.drop_entries("fish_add_path /x /a", ["/a"]), "fish_add_path /x")
        self.assertIsNone(envclean.drop_entries('export PATH="/a":$PATH', ["/a"]))
        self.assertIsNone(envclean.drop_entries("export PATH=$PATH # /a", ["/a"]))

    def test_an_unrecorded_assignment_keeps_its_line(self):
        path = self.rc(".zshrc", "\n".join([
            f"export PATH={self.ports_prefix}/bin:$PATH EDITOR=vim",
            f"export PATH={self.ports_prefix}/bin LESS=-R",
            f"export PATH={self.ports_prefix}/bin:\\",
            f"{self.brew_prefix}/bin:$PATH",
        ]) + "\n")
        edit = self.edit(self.ports_removed(), path)
        lines = edit.new_text.splitlines()
        self.assertEqual(lines[0], "export PATH=$PATH EDITOR=vim")
        self.assertEqual(lines[1:], [f"export PATH={self.ports_prefix}/bin LESS=-R",
                                     f"export PATH={self.ports_prefix}/bin:\\", f"{self.brew_prefix}/bin:$PATH"])
        self.assertTrue(any(n.startswith(f"line 2 names {self.ports_prefix} and holds more") for n in edit.notes))
        self.assertTrue(any(n.startswith("line 3 left as it is: it opens or continues a compound command")
                            for n in edit.notes))

    def test_another_command_on_the_line_stays(self):
        intel = b.instance(self.tmp, Manager.BREW, "usr/local", roots=b.USR_LOCAL_ROOTS)
        shellenv = f'eval "$({intel.prefix}/bin/brew shellenv)"; eval "$(rbenv init -)"'
        zprofile = self.rc(".zprofile", shellenv + "\n")
        zshrc = self.rc(".zshrc", f'export PATH="{self.ports_prefix}/bin:$PATH"; source ~/.extra\n'
                                  f"PATH={self.ports_prefix}/sbin:$PATH; export PATH\n")
        fish = self.rc(".config/fish/config.fish", f"set -gx PATH {self.ports_prefix}/bin $PATH; set -gx EDITOR nvim\n")
        tcshrc = self.rc(".tcshrc", f"setenv PATH {self.ports_prefix}/bin:${{PATH}}; setenv EDITOR vim\n")
        surv = self.survivors([self.brew], [self.ports, intel], self.brew, [self.brew, self.ports, intel])
        edits = self.compute(surv)
        self.assertEqual((self.edit(edits, zprofile).changed, self.edit(edits, zprofile).notes), (False, [
            f"line 1 names {intel.prefix} and holds more than this cleanup removes: edit it by hand: {shellenv}"]))
        self.assertEqual(self.edit(edits, zshrc).new_text, 'export PATH="$PATH"; source ~/.extra\n')
        self.assertEqual(self.edit(edits, fish).new_text, "set -gx PATH $PATH; set -gx EDITOR nvim\n")
        self.assertEqual(self.edit(edits, tcshrc).new_text, "setenv PATH ${PATH}; setenv EDITOR vim\n")

    def test_a_line_with_an_entry_that_stays_is_left_alone(self):
        text = "\n".join([
            'export PATH="$HOME/.local/bin:$(brew --prefix)/opt/python/libexec/bin:$PATH"',
            'export PATH="$(brew --prefix)/opt/python/libexec/bin:$PATH"',
            f"fpath=({self.brew_prefix}/share/zsh/site-functions $HOME/.zsh/completions $fpath)",
            f'export PKG_CONFIG_PATH="{self.brew_prefix}/lib/pkgconfig:{self.ports_prefix}/lib/pkgconfig"',
        ]) + "\n"
        path = self.rc(".zprofile", text)
        edit = self.edit(self.compute(self.survivors([self.ports], [self.brew], self.ports)), path)
        lines = text.splitlines()
        self.assertEqual(edit.new_text.splitlines(), [lines[0], f"true  # brew-ports: {self.brew_prefix} removed: "
                                                                f"{lines[1]}"] + lines[2:])
        self.assertEqual([note.split(":")[0] for note in edit.notes if "holds more" in note],
                         [f"line {n} names {self.brew_prefix} and holds more than this cleanup removes"
                          for n in (1, 3, 4)])

    def test_dyld_and_build_exports_go(self):
        path = self.rc(".zshrc", "\n".join([
            f"export DYLD_LIBRARY_PATH={self.ports_prefix}/lib:$DYLD_LIBRARY_PATH",
            f'export PKG_CONFIG_PATH="{self.ports_prefix}/lib/pkgconfig"',
            'export LDFLAGS="-L/opt/other-bpu/lib"',
            f'export CPPFLAGS="-I{self.brew_prefix}/include"',
        ]) + "\n")
        edit = self.edit(self.ports_removed(), path)
        self.assertEqual(edit.new_text,
                         f'export LDFLAGS="-L/opt/other-bpu/lib"\nexport CPPFLAGS="-I{self.brew_prefix}/include"\n')
        self.assertEqual([op.split(":")[0] for op in edit.ops], ["build exports, line 1", "build exports, line 2"])

    def test_a_flag_that_names_no_removed_prefix_keeps_its_line(self):
        cflags = f'export CFLAGS="-O2 -I{self.ports_prefix}/include"'
        path = self.rc(".zshrc", f"{cflags}\n"
                                  f'export LDFLAGS="-L{self.ports_prefix}/lib -Wl,-rpath,{self.ports_prefix}/lib '
                                  '$LDFLAGS"\n')
        edit = self.edit(self.ports_removed(), path)
        self.assertEqual(edit.new_text, cflags + "\n")
        self.assertEqual([op.split(":")[0] for op in edit.ops], ["build exports, line 2"])
        self.assertEqual(edit.notes, [f"line 1 names {self.ports_prefix} and holds more than this cleanup removes: "
                                      f"edit it by hand: {cflags}"])

    def test_a_csh_set_of_several_variables_keeps_the_others(self):
        path = self.rc(".tcshrc", f'set path = ( {self.ports_prefix}/bin $path ) prompt = "%m> "\n'
                                  f"set path = {self.ports_prefix}/bin cdpath = ~/src\n")
        edit = self.edit(self.ports_removed(), path)
        self.assertEqual(edit.new_text, 'set path = ( $path ) prompt = "%m> "\n'
                                        f"set path = {self.ports_prefix}/bin cdpath = ~/src\n")
        self.assertEqual([note.split(":")[0] for note in edit.notes],
                         [f"line 2 names {self.ports_prefix} and holds more than this cleanup removes",
                          "dead entries, line 2"])

    def test_a_bare_name_in_a_csh_set_is_another_variable(self):
        path = self.rc(".tcshrc", f"set path = ( {self.ports_prefix}/bin $path ) filec\n"
                                  f"set path = {self.ports_prefix}/bin autolist\n")
        edit = self.edit(self.ports_removed(), path)
        self.assertEqual(edit.new_text, "set path = ( $path ) filec\n"
                                        f"set path = {self.ports_prefix}/bin autolist\n")
        self.assertEqual([note.split(":")[0] for note in edit.notes],
                         [f"line 2 names {self.ports_prefix} and holds more than this cleanup removes",
                          "dead entries, line 2"])

    def test_a_reset_and_a_missing_directory_are_noted(self):
        path = self.rc(".zshrc", "export PATH=/usr/bin:/bin\nexport PATH=$HOME/nonexistent-bpu/bin:$PATH\n")
        edit = self.edit(self.ports_removed(), path)
        self.assertFalse(edit.changed)
        self.assertEqual(edit.notes, [
            "dead entries, line 1: drops $PATH, which discards /etc/paths: export PATH=/usr/bin:/bin",
            "dead entries, line 2: $HOME/nonexistent-bpu/bin does not exist"])


class InstallerBlockTest(CleanupTest):
    """Tests of the MacPorts installer blocks"""

    def test_a_user_line_inside_an_installer_block_stays(self):
        text = fixture("zprofile-macports.txt", PORTS=self.ports_prefix, BREW=self.brew_prefix)
        path = self.rc(".zprofile", text)
        edit = self.edit(self.ports_removed(), path)
        expected = "".join(line for number, line in enumerate(text.splitlines(True), 1)
                           if number not in (2, 3, 5, 8, 9, 10))
        self.assertEqual(edit.new_text, expected)
        self.assertIn('export PATH="$HOME/bin:$PATH"', edit.new_text)
        self.assertIn("manager setup, lines 2 and 5: removed the markers of the MacPorts installer block for PATH",
                      edit.ops)

    def test_the_block_of_a_surviving_instance_stays(self):
        path = self.rc(".zprofile", fixture("zprofile-macports.txt", PORTS=self.ports_prefix, BREW=self.brew_prefix))
        edits = self.compute(self.survivors([self.ports], [self.brew], self.ports))
        edit = self.edit(edits, path)
        self.assertEqual([op.split(":")[0] for op in edit.ops], ["manager setup, line 12"])


class ShellenvTest(CleanupTest):
    """Tests of the `brew shellenv` lines once Homebrew is removed, or while another Homebrew survives"""

    def test_a_pathless_shellenv_line_goes_without_homebrew(self):
        text = "\n".join([
            'eval "$(brew shellenv)"',
            f'[ -x {self.brew_prefix}/bin/brew ] && eval "$({self.brew_prefix}/bin/brew shellenv)"',
            "source $(brew --prefix)/share/zsh-autosuggestions/zsh-autosuggestions.zsh",
            'eval "$(/opt/elsewhere-bpu/bin/brew shellenv)"',
        ]) + "\n"
        path = self.rc(".zprofile", text)
        edit = self.edit(self.compute(self.survivors([self.ports], [self.brew], self.ports)), path)
        self.assertEqual(edit.new_text, f"true  # brew-ports: {self.brew_prefix} removed: source "
                                        "$(brew --prefix)/share/zsh-autosuggestions/zsh-autosuggestions.zsh\n"
                                        'eval "$(/opt/elsewhere-bpu/bin/brew shellenv)"\n')
        self.assertEqual([op.split(":")[0] for op in edit.ops],
                         ["manager setup, line 1", "manager setup, line 2", "sourced files, line 3"])

    def test_a_pathless_shellenv_line_stays_with_homebrew(self):
        other = b.instance(self.tmp, Manager.BREW, "usr/local", roots=b.USR_LOCAL_ROOTS)
        path = self.rc(".zprofile", f'eval "$(brew shellenv)"\neval "$({self.brew_prefix}/bin/brew shellenv)"\n')
        surv = self.survivors([self.ports, other], [self.brew], self.ports, [self.brew, self.ports, other])
        edit = self.edit(self.compute(surv), path)
        self.assertEqual(edit.new_text, 'eval "$(brew shellenv)"\n')


class SourceLinesTest(CleanupTest):
    """Tests of the lines that source, evaluate or complete with the files of a removed prefix"""

    GUARDED = [
        "if [ -f {P}/etc/profile.d/bash_completion.sh ]; then",
        "    . {P}/etc/profile.d/bash_completion.sh",
        "fi",
        "[ -f {P}/share/fzf/key-bindings.bash ] && source {P}/share/fzf/key-bindings.bash",
        'eval "$({P}/bin/direnv hook bash)"',
        "complete -C {B}/bin/aws_completer aws",
        "# source {P}/etc/commented-out.sh",
        "source ~/.bash_aliases",
    ]

    def guarded(self):
        """Write a `.bashrc` of guarded and other lines that name the two prefixes

        @returns  its path
        """
        return self.rc(".bashrc", "\n".join(self.GUARDED).format(P=self.ports_prefix, B=self.brew_prefix) + "\n")

    def test_a_guarded_dot_line_is_neutralised(self):
        path = self.guarded()
        edit = self.edit(self.ports_removed(), path)
        lines = edit.new_text.splitlines()
        self.assertEqual(lines[:3], [f"if [ -f {self.ports_prefix}/etc/profile.d/bash_completion.sh ]; then",
                                     f"    . {self.ports_prefix}/etc/profile.d/bash_completion.sh", "fi"])
        self.assertEqual(lines[3], f"true  # brew-ports: {self.ports_prefix} removed: "
                                   f"[ -f {self.ports_prefix}/share/fzf/key-bindings.bash ] && source "
                                   f"{self.ports_prefix}/share/fzf/key-bindings.bash")
        self.assertEqual(lines[4], f"true  # brew-ports: {self.ports_prefix} removed: "
                                   f'eval "$({self.ports_prefix}/bin/direnv hook bash)"')
        self.assertEqual(lines[5:], [f"complete -C {self.brew_prefix}/bin/aws_completer aws",
                                     f"# source {self.ports_prefix}/etc/commented-out.sh", "source ~/.bash_aliases"])
        self.assertEqual([note.split(":")[0] for note in edit.notes], ["line 1 left as it is", "line 2 left as it is"])
        self.assertTrue(edit.notes[1].startswith("line 2 left as it is: it opens or continues a compound command"))
        run_dir = self.run_dir()
        runner = b.fake_runner(run_dir)
        result = envclean.apply(runner, run_dir, [edit], b.FakeRootFiles(runner))
        self.assertEqual(result.written, [os.path.realpath(path)])
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), edit.new_text)

    @unittest.skipUnless(os.access("/bin/bash", os.X_OK), "no /bin/bash")
    def test_bash_accepts_true_and_rejects_an_empty_branch(self):
        path = self.guarded()
        edit = self.edit(self.ports_removed(), path)
        runner = r.CommandRunner(console=b.QuietConsole(), environ={}, out_dir=self.path("out"))
        self.assertTrue(env_shell.syntax_check(runner, "bash", edit.new_text, tmp_dir=self.tmp))
        emptied = "\n".join(line for number, line in enumerate(edit.new_text.splitlines(), 1) if number != 2) + "\n"
        self.assertFalse(env_shell.syntax_check(runner, "bash", emptied, tmp_dir=self.tmp))


class OrderTest(CleanupTest):
    """PATH line and PATH order: the target Homebrew is primary, the MacPorts instance survives"""

    def order(self, login="/bin/zsh", **kw):
        """Compute the edits when both instances survive, the Homebrew one primary

        @param login  the login shell
        @param kw     further options of `compute`
        @returns      the edits
        """
        return self.compute(self.survivors([self.brew, self.ports], [], self.brew), login=login, **kw)

    def shellenv(self):
        """Return the PATH line of the Homebrew instance

        @returns  its `brew shellenv` line
        """
        return f'eval "$({self.brew_prefix}/bin/brew shellenv)"'

    def test_the_line_moves_below_a_prepend_in_its_file(self):
        path = self.rc(".zprofile", f'{self.shellenv()}\n'
                                    f'export PATH="{self.ports_prefix}/bin:{self.ports_prefix}/sbin:$PATH"\n')
        edit = self.edit(self.order(), path)
        self.assertEqual(edit.new_text,
                         f'export PATH="{self.ports_prefix}/bin:{self.ports_prefix}/sbin:$PATH"\n{self.shellenv()}\n')
        self.assertEqual(edit.ops, [f"PATH order, line 1: moved below line 2, the PATH line of {self.ports_prefix}"])

    def test_a_copy_goes_after_a_prepend_in_a_later_file(self):
        zprofile = self.rc(".zprofile", self.shellenv() + "\n")
        zshrc = self.rc(".zshrc", f"alias ll='ls -l'\n  export PATH={self.ports_prefix}/bin:$PATH\nbindkey -e\n")
        edits = self.order()
        self.assertEqual([e.path for e in edits if e.changed], [zshrc])
        self.assertEqual(self.edit(edits, zshrc).new_text,
                         f"alias ll='ls -l'\n  export PATH={self.ports_prefix}/bin:$PATH\n  {self.shellenv()}\n"
                         "bindkey -e\n")
        self.assertNotIn(zprofile, [e.path for e in edits])

    def test_a_copy_goes_after_the_end_of_an_installer_block(self):
        self.rc(".zprofile", self.shellenv() + "\n")
        text = fixture("zprofile-macports.txt", PORTS=self.ports_prefix, BREW="/nonexistent-bpu")
        zshrc = self.rc(".zshrc", text)
        lines = self.edit(self.order(), zshrc).new_text.splitlines()
        self.assertEqual(lines[5], self.shellenv())
        self.assertTrue(lines[4].startswith("# Finished adapting your PATH"))

    def test_zprofile_gets_the_line_despite_zshenv(self):
        self.rc(".zshenv", self.shellenv() + "\n")
        edits = self.order()
        edit = self.edit(edits, os.path.join(self.home, ".zprofile"))
        self.assertEqual((edit.old_text, edit.new_text), (None, self.shellenv() + "\n"))
        self.assertEqual(edit.ops, [f"PATH line: added the line of {self.brew_prefix}"])
        self.assertTrue(edit.diff.startswith("--- /dev/null\n"))

    def test_a_two_architecture_block_is_left_alone(self):
        intel = b.instance(self.tmp, Manager.BREW, "usr/local", roots=b.USR_LOCAL_ROOTS)
        text = (f'if [ "$(uname -m)" = arm64 ]; then\n  {self.shellenv()}\nelse\n'
                f'  eval "$({intel.prefix}/bin/brew shellenv)"\nfi\n')
        path = self.rc(".zprofile", text)
        for removed, note in (([], f"PATH order: line 4, the PATH line of {intel.prefix}, is inside a compound"),
                              ([intel], "line 4 left as it is: it opens or continues a compound command")):
            with self.subTest(removed=[i.prefix for i in removed]):
                surviving = [self.brew] + [i for i in [intel] if i not in removed]
                surv = self.survivors(surviving, removed, self.brew, [self.brew, intel])
                edit = self.edit(self.compute(surv, login="/bin/zsh"), path)
                self.assertEqual((edit.new_text, edit.ops), (text, []))
                self.assertEqual([n[:len(note)] for n in edit.notes], [note])

    def test_duplicate_shellenv_lines_collapse_to_the_last(self):
        path = self.rc(".zprofile", f"{self.shellenv()}\nexport PATH=$HOME/bin:$PATH\n{self.shellenv()}\n")
        edit = self.edit(self.order(), path)
        self.assertEqual(edit.new_text, f"export PATH=$HOME/bin:$PATH\n{self.shellenv()}\n")

    def test_each_shell_gets_its_syntax_in_its_login_file(self):
        cases = [("/bin/bash", self.brew, ".bash_profile", self.shellenv()),
                 ("/bin/tcsh", self.ports, ".tcshrc",
                  f'setenv PATH "{self.ports_prefix}/bin:{self.ports_prefix}/sbin:$PATH"'),
                 ("/opt/homebrew-bpu/bin/fish", self.ports, ".config/fish/config.fish",
                  f"set -gx PATH {self.ports_prefix}/bin {self.ports_prefix}/sbin $PATH"),
                 ("/bin/sh", self.brew, ".profile", self.shellenv()),
                 ("/bin/csh", self.brew, ".tcshrc", f"eval `{self.brew_prefix}/bin/brew shellenv`")]
        for login, primary, name, line in cases:
            with self.subTest(login=login):
                surv = self.survivors([self.brew, self.ports], [], primary)
                edit = self.edit(self.compute(surv, login=login), os.path.join(self.home, name))
                self.assertEqual(edit.new_text, line + "\n")

    def test_the_existing_login_file_and_zdotdir_are_used(self):
        profile = self.rc(".profile", "umask 022\n")
        edit = self.edit(self.order(login="/bin/bash"), profile)
        self.assertEqual(edit.new_text, f"umask 022\n{self.shellenv()}\n")
        self.rc(".zshenv", "export ZDOTDIR=$HOME/zd\n")
        edits = self.order()
        self.assertEqual(self.edit(edits, os.path.join(self.home, "zd", ".zprofile")).new_text, self.shellenv() + "\n")

    def test_no_line_when_the_live_path_has_bin_first(self):
        environ = {"HOME": self.home, "PATH": f"{self.brew_prefix}/bin:/usr/bin:/bin"}
        edits = self.order(environ=environ)
        self.assertEqual([e.kind for e in edits], ["note"])
        self.assertEqual(edits[0].notes, [f"PATH line: {self.brew_prefix}/bin already comes before /usr/bin on the "
                                          "live PATH, so no PATH line is added"])
        environ["PATH"] = f"/usr/bin:/bin:{self.brew_prefix}/bin"
        edit = self.edit(self.order(environ=environ), os.path.join(self.home, ".zprofile"))
        self.assertEqual(edit.new_text, self.shellenv() + "\n")

    def test_no_order_change_for_an_unknown_login_shell(self):
        edits = self.order(login="/bin/ksh")
        self.assertEqual([e.kind for e in edits], ["note"])
        self.assertIn("none of zsh, bash, sh, tcsh, csh, fish", edits[0].notes[0])


class EtcTest(CleanupTest):
    """Tests of the system paths edits and of the GUI PATH command"""

    def test_system_paths_files_are_rewritten_or_removed(self):
        paths = self.etc_file("paths", f"/usr/local/bin\n/usr/bin\n/bin\n{self.ports_prefix}/bin\n")
        macports = self.etc_file("paths.d/macports", f"{self.ports_prefix}/bin\n{self.ports_prefix}/sbin\n\n")
        mixed = self.etc_file("paths.d/mixed", f"{self.ports_prefix}/bin\n/opt/X11/bin\n")
        self.etc_file("paths.d/homebrew", f"{self.brew_prefix}/bin\n")
        edits = [e for e in self.ports_removed() if e.kind == "etc"]
        self.assertEqual([(e.path, e.new_text, e.etc_rel) for e in edits], [
            (paths, "/usr/local/bin\n/usr/bin\n/bin\n", "paths"),
            (macports, None, os.path.join("paths.d", "macports")),
            (mixed, "/opt/X11/bin\n", os.path.join("paths.d", "mixed"))])
        run_dir = self.run_dir()
        runner = b.fake_runner(run_dir)
        runner.phase = 7
        roots = b.FakeRootFiles(runner)
        result = envclean.apply(runner, run_dir, edits, roots)
        self.assertEqual(roots.writes, [(os.path.realpath(paths), "/usr/local/bin\n/usr/bin\n/bin\n"),
                                        (os.path.realpath(mixed), "/opt/X11/bin\n")])
        self.assertEqual(roots.backups, [os.path.realpath(macports)])
        self.assertIn((r.SUDO, "-n", "--", r.RM, os.path.realpath(macports)), runner.calls)
        self.assertEqual(result.removed, [os.path.realpath(macports)])
        with open(run_dir.sub("backup", "etc", "paths.d", "mixed"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), f"{self.ports_prefix}/bin\n/opt/X11/bin\n")
        writes = [e for e in run_dir.journal.entries() if e.get("kind") == "write"]
        self.assertEqual([(w["path"], w["root"], w["action_id"].split(".")[1]) for w in writes],
                         [(os.path.realpath(paths), True, "write"), (os.path.realpath(mixed), True, "write")])

    def test_the_stock_usr_local_lines_are_never_removed(self):
        ul = make_instance(Manager.BREW, "/usr/local", identity=system.identity("/usr/local") or (0, 0),
                           spellings=("/usr/local",), owned_roots=("/usr/local",))
        self.etc_file("paths", "/usr/local/bin\n/usr/local/sbin\n/usr/bin\n")
        self.etc_file("paths.d/tools", "/usr/local/sbin\n")
        path = self.rc(".zshrc", "export PATH=/usr/local/bin:/usr/local/opt/x/bin:$PATH\n")
        surv = self.survivors([self.brew], [ul], self.brew, [self.brew, ul])
        edits = self.compute(surv)
        self.assertEqual([e for e in edits if e.kind == "etc"], [])
        self.assertEqual(self.edit(edits, path).new_text, "export PATH=/usr/local/bin:$PATH\n")

    def test_the_gui_path_command_is_printed_never_run(self):
        edits = self.ports_removed(gui=[f"{self.ports_prefix}/bin", "/usr/bin", "/bin"])
        [edit] = [e for e in edits if e.kind == "launchd"]
        self.assertEqual(edit.command, ["sudo", "launchctl", "config", "user", "path", "/usr/bin:/bin"])
        self.assertTrue(edit.manual.startswith("run by hand: sudo launchctl config user path"))
        run_dir = self.run_dir()
        runner = b.fake_runner(run_dir)
        result = envclean.apply(runner, run_dir, edits, b.FakeRootFiles(runner))
        self.assertEqual(result.manual, [envclean.GUI_PATH])
        self.assertFalse([c for c in runner.calls if "launchctl" in " ".join(c)])
        self.assertIn("run by hand: sudo launchctl config user path /usr/bin:/bin", b.console_text(runner))


class OwnershipTest(CleanupTest):
    """Tests of the files the tool writes through a symlink, leaves to their owner, or never edits"""

    def test_a_symlinked_rc_file_is_written_through(self):
        real = self.rc("dotfiles/zshrc", f"export PATH={self.ports_prefix}/bin:$PATH\nalias ll='ls -l'\n")
        link = os.path.join(self.home, ".zshrc")
        os.symlink(real, link)
        inode = os.stat(real).st_ino
        edit = self.edit(self.ports_removed(), link)
        self.assertEqual(edit.realpath, real)
        run_dir = self.run_dir()
        runner = b.fake_runner(run_dir)
        runner.phase = 7
        result = envclean.apply(runner, run_dir, [edit], b.FakeRootFiles(runner))
        self.assertEqual(result.written, [real])
        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.stat(real).st_ino, inode)
        with open(real, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "alias ll='ls -l'\n")
        with open(run_dir.backup_path(real), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), f"export PATH={self.ports_prefix}/bin:$PATH\nalias ll='ls -l'\n")
        [write] = [e for e in run_dir.journal.entries() if e.get("kind") == "write"]
        self.assertEqual((write["path"], write["named"], write["action_id"]),
                         (real, link, f"7.write.{state.slug(real)}"))
        self.assertEqual(run_dir.journal.result(7, write["action_id"]), "ok")
        self.assertEqual(len(write["sha256"]), 64)

    def test_a_file_owned_by_someone_else_is_never_written(self):
        store = self.path("nix", "store", "abc-zshrc")
        os.makedirs(os.path.dirname(store))
        with open(store, "w", encoding="utf-8") as fh:
            fh.write(f"export PATH={self.ports_prefix}/bin:$PATH\n")
        os.symlink(store, os.path.join(self.home, ".zshrc"))
        edit = self.edit(self.ports_removed(uid=os.getuid() + 1), os.path.join(self.home, ".zshrc"))
        self.assertEqual(edit.manual, f"{store} belongs to uid {os.getuid()}, not to you: make this edit by hand")
        self.assertEqual(edit.new_text, "")
        run_dir = self.run_dir()
        runner = b.fake_runner(run_dir)
        result = envclean.apply(runner, run_dir, [edit], b.FakeRootFiles(runner))
        self.assertEqual((result.manual, result.written), ([edit.path], []))
        with open(store, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), f"export PATH={self.ports_prefix}/bin:$PATH\n")
        self.assertFalse(os.path.exists(run_dir.sub("backup")))
        self.assertIn(f"-export PATH={self.ports_prefix}/bin:$PATH", b.console_text(runner))

    def test_etc_zprofile_is_never_edited(self):
        path = self.etc_file("zprofile",
                             f"eval `/usr/libexec/path_helper -s`\nexport PATH={self.ports_prefix}/bin:$PATH\n")
        edit = self.edit(self.ports_removed(), path)
        self.assertEqual(edit.manual, f"the tool never edits {path}: make this edit by hand")
        self.assertEqual(edit.new_text, "eval `/usr/libexec/path_helper -s`\n")


class ApplyTest(CleanupTest):
    """Tests of `apply`: the syntax check, a login file it creates and the first-copy backup"""

    def test_a_rewrite_the_parser_rejects_is_not_written(self):
        text = f"export PATH={self.ports_prefix}/bin:$PATH\nalias ll='ls -l'\n"
        path = self.rc(".bashrc", text)
        edit = self.edit(self.ports_removed(), path)
        self.assertEqual(edit.new_text, "alias ll='ls -l'\n")
        checked: list[str] = []
        run_dir = self.run_dir()
        runner = b.fake_runner(run_dir, b.syntax_responder(lambda t: t == edit.new_text, calls=checked))
        result = envclean.apply(runner, run_dir, [edit], b.FakeRootFiles(runner))
        self.assertEqual((result.rejected, result.written), ([path], []))
        self.assertEqual(checked, [edit.new_text, text])
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), text)
        self.assertIn("not written: the bash parser rejects the rewrite", b.console_text(runner))

    def test_a_file_the_parser_already_rejects_is_written(self):
        text = f"then BROKEN-bpu\nexport PATH={self.ports_prefix}/bin:$PATH\n"
        path = self.rc(".bashrc", text)
        edit = self.edit(self.ports_removed(), path)
        run_dir = self.run_dir()
        runner = b.fake_runner(run_dir, b.syntax_responder(lambda t: "BROKEN-bpu" in t))
        result = envclean.apply(runner, run_dir, [edit], b.FakeRootFiles(runner))
        self.assertEqual(result.written, [os.path.realpath(path)])

    def test_a_created_login_file_and_the_first_copy_backup(self):
        surv = self.survivors([self.brew, self.ports], [], self.brew)
        edits = self.compute(surv, login="/bin/zsh")
        run_dir = self.run_dir()
        runner = b.fake_runner(run_dir)
        result = envclean.apply(runner, run_dir, edits, b.FakeRootFiles(runner))
        zprofile = os.path.join(self.home, ".zprofile")
        self.assertEqual(result.written, [zprofile])
        self.assertEqual(os.stat(zprofile).st_mode & 0o777, 0o644)
        self.assertFalse(os.path.exists(run_dir.backup_path(zprofile)))
        rc = self.rc(".zshrc", f"export PATH={self.ports_prefix}/bin:$PATH\n")
        first = self.edit(self.ports_removed(), rc)
        envclean.apply(runner, run_dir, [first], b.FakeRootFiles(runner))
        with open(rc, "w", encoding="utf-8") as fh:
            fh.write(f"export PATH={self.ports_prefix}/sbin:$PATH\n")
        envclean.apply(runner, run_dir, [self.edit(self.ports_removed(), rc)], b.FakeRootFiles(runner))
        with open(run_dir.backup_path(rc), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), f"export PATH={self.ports_prefix}/bin:$PATH\n")


if __name__ == "__main__":
    unittest.main()

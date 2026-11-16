"""Shell analysis, the login shell and the syntax check of rewritten shell files"""

import json
import os
import unittest
from unittest import mock

from brew_ports import model, runner as r
from brew_ports.env import shell as sh
from tests.unit.test_env_paths import EnvTest, fixture


class ShellTest(EnvTest):
    """The base of the shell analysis tests: a home, an `/etc`, and a Homebrew and a MacPorts instance"""

    def setUp(self):
        super().setUp()
        self.home = self.path("Users", "alice")
        self.etc = self.path("etc")
        self.mkdirs(self.home, self.etc)
        self.brew = self.instance(model.Manager.BREW, "opt/homebrew")
        self.ports = self.instance(model.Manager.PORTS, "opt/local")
        self.brew_prefix, self.ports_prefix = self.brew.prefix, self.ports.prefix
        self.touch(os.path.join(self.brew_prefix, "bin", "brew"), b"#!/bin/bash\n", 0o755)
        self.mkdirs(os.path.join(self.brew_prefix, "sbin"), os.path.join(self.ports_prefix, "bin"),
                    os.path.join(self.ports_prefix, "sbin"))

    def rc(self, name, text):
        """Write a shell file below the home

        @param name  its path below the home, with `/` separators
        @param text  its text
        @returns     its path
        """
        return self.touch(os.path.join(self.home, *name.split("/")), text.encode("utf-8"))

    def analyse(self, environ=None, login=None, responses=None, instances=None):
        """Analyse the home's shell files on a fake runner whose probes print nothing by default

        @param environ    the environment; None for a PATH of `/usr/bin:/bin`
        @param login      the path of the login shell, or None
        @param responses  the canned responses, by argv
        @param instances  the instances; None for the Homebrew and the MacPorts one
        @returns          the analysis
        """
        fake = self.runner(responses, default=r.FakeResponse(exit=0, stdout=""))
        env = {"PATH": "/usr/bin:/bin"} if environ is None else environ
        return sh.analyse(fake, self.home, env, instances or [self.brew, self.ports], login, etc_dir=self.etc)

    @staticmethod
    def records(analysis, path):
        """Return the records of one file

        @param analysis  the shell analysis
        @param path      the file
        @returns         its records, in line order
        """
        return [rec for rec in analysis.records if rec.file == path]


class ZdotdirTest(ShellTest):
    """Tests of `ZDOTDIR`: set in `~/.zshenv`, in the environment, or equal to the home"""

    def test_zdotdir_from_zshenv(self):
        self.rc(".zshenv", '# zsh reads this first\nexport ZDOTDIR="$HOME/.config/zsh"\n')
        zprofile = self.rc(".config/zsh/.zprofile", f'eval "$({self.brew_prefix}/bin/brew shellenv)"\n')
        self.rc(".zprofile", "export PATH=/ignored/bin:$PATH\n")
        a = self.analyse()
        self.assertEqual((a.zdotdir, a.zdotdir_source), (os.path.join(self.home, ".config", "zsh"), "~/.zshenv"))
        paths = [f.path for f in a.files]
        self.assertIn(zprofile, paths)
        self.assertIn(os.path.join(self.home, ".zshenv"), paths)
        self.assertNotIn(os.path.join(self.home, ".zprofile"), paths)
        self.assertEqual([(x.kind, x.brew, x.instance_prefixes) for x in self.records(a, zprofile)],
                         [("shellenv", os.path.join(self.brew_prefix, "bin", "brew"), [self.brew_prefix])])

    def test_zdotdir_with_an_xdg_default(self):
        self.rc(".zshenv", "ZDOTDIR=${XDG_CONFIG_HOME:-$HOME/.config}/zsh\n")
        self.assertEqual(self.analyse().zdotdir, os.path.join(self.home, ".config", "zsh"))
        xdg = self.path("xdg")
        self.assertEqual(self.analyse({"XDG_CONFIG_HOME": xdg}).zdotdir, os.path.join(xdg, "zsh"))

    def test_zdotdir_from_the_environment_and_from_home(self):
        zd = os.path.join(self.home, "zd")
        a = self.analyse({"PATH": "/usr/bin", "ZDOTDIR": zd})
        self.assertEqual((a.zdotdir, a.zdotdir_source), (zd, "environment"))
        self.assertIn(os.path.join(zd, ".zshrc"), [f.path for f in a.files])
        self.rc(".zshenv", "export ZDOTDIR=$HOME\n")
        self.assertEqual((self.analyse().zdotdir, self.analyse().zdotdir_source), (None, None))
        self.rc(".zshenv", "export ZDOTDIR=$UNSET_BPU_VARIABLE/zsh\n")
        self.assertIsNone(self.analyse().zdotdir)


class LineRecordsTest(ShellTest):
    """Tests of the line records: installer blocks, PATH lines, `shellenv`, sourced files and build exports"""

    def test_installer_blocks(self):
        path = self.rc(".zprofile", fixture("zprofile-macports.txt", PORTS=self.ports_prefix, BREW=self.brew_prefix))
        a = self.analyse()
        self.assertEqual([(b.file, b.start, b.end, b.var) for b in a.blocks],
                         [(path, 2, 5, "PATH"), (path, 8, 10, "MANPATH")])
        got = [(x.lineno, x.kind, x.var, x.block, x.instance_prefixes) for x in self.records(a, path)]
        self.assertEqual(got, [
            (2, "marker", "PATH", 0, []), (3, "assign", "PATH", 0, [self.ports_prefix]), (4, "assign", "PATH", 0, []),
            (5, "marker", "PATH", 0, []), (8, "marker", "MANPATH", 1, []),
            (9, "assign", "MANPATH", 1, [self.ports_prefix]), (10, "marker", "MANPATH", 1, []),
            (12, "shellenv", None, None, [self.brew_prefix])])
        user_line = self.records(a, path)[2]
        self.assertEqual(user_line.entries[0].path, os.path.join(self.home, "bin"))

    def test_a_path_line_with_user_entries(self):
        path = self.rc(".bash_profile", f'export PATH="{self.ports_prefix}/bin:$HOME/.cargo/bin:/usr/local/bin:'
                                        f'{self.ports_prefix}/sbin:$PATH"\n')
        [rec] = self.records(self.analyse(), path)
        self.assertEqual((rec.kind, rec.var, rec.self_ref, rec.position, rec.instance_prefixes),
                         ("assign", "PATH", True, "prepend", [self.ports_prefix]))
        self.assertEqual([(e.text, e.instance_prefix, e.usr_local) for e in rec.entries], [
            (self.ports_prefix + "/bin", self.ports_prefix, False), ("$HOME/.cargo/bin", None, False),
            ("/usr/local/bin", None, True), (self.ports_prefix + "/sbin", self.ports_prefix, False)])
        self.assertEqual((rec.entries[1].path, rec.entries[1].exists),
                         (os.path.join(self.home, ".cargo", "bin"), False))
        self.assertTrue(rec.entries[0].exists)

    def test_a_guarded_dot_line_and_other_lines_naming_a_prefix(self):
        path = self.rc(".bashrc", "\n".join([
            f"if [ -f {self.ports_prefix}/etc/profile.d/bash_completion.sh ]; then",
            f"    . {self.ports_prefix}/etc/profile.d/bash_completion.sh",
            "fi",
            f"[ -f {self.ports_prefix}/share/fzf/key-bindings.bash ] && "
            f"source {self.ports_prefix}/share/fzf/key-bindings.bash",
            f'eval "$({self.ports_prefix}/bin/direnv hook bash)"',
            f"complete -C {self.brew_prefix}/bin/aws_completer aws",
            f"# source {self.ports_prefix}/etc/commented-out.sh",
            "source ~/.bash_aliases",
        ]) + "\n")
        got = [(x.lineno, x.kind, x.command, x.compound, x.instance_prefixes)
               for x in self.records(self.analyse(), path)]
        self.assertEqual(got, [(1, "source", "other", True, [self.ports_prefix]),
                               (2, "source", ".", True, [self.ports_prefix]),
                               (4, "source", "source", False, [self.ports_prefix]),
                               (5, "source", "eval", False, [self.ports_prefix]),
                               (6, "source", "other", False, [self.brew_prefix])])

    def test_shellenv_forms_and_duplicates(self):
        brew = os.path.join(self.brew_prefix, "bin", "brew")
        zshrc = self.rc(".zshrc", "\n".join([
            f'eval "$({brew} shellenv)"',
            'eval "$(/opt/elsewhere-bpu/bin/brew shellenv)"',
            f'[ -x {brew} ] && eval "$({brew} shellenv)"',
            'eval "$(brew shellenv)"',
            'eval "$(brew shellenv zsh)"',
            "source $(brew --prefix)/share/zsh-autosuggestions/zsh-autosuggestions.zsh",
            "alias mybrew='echo mybrew shellenv'",
        ]) + "\n")
        tcshrc = self.rc(".tcshrc", f"eval `{brew} shellenv`\n")
        fish = self.rc(".config/fish/config.fish", f"{brew} shellenv | source\neval ({brew} shellenv)\n")
        a = self.analyse()
        got = [(x.lineno, x.kind, x.brew, x.duplicate, x.instance_prefixes) for x in self.records(a, zshrc)]
        self.assertEqual(got, [(1, "shellenv", brew, False, [self.brew_prefix]),
                               (2, "shellenv", "/opt/elsewhere-bpu/bin/brew", False, []),
                               (3, "shellenv", brew, True, [self.brew_prefix]), (4, "shellenv", "", False, []),
                               (5, "shellenv", "", True, []), (6, "source", "", False, [])])
        self.assertEqual([(x.kind, x.brew) for x in self.records(a, tcshrc)], [("shellenv", brew)])
        self.assertEqual([(x.kind, x.duplicate) for x in self.records(a, fish)],
                         [("shellenv", False), ("shellenv", True)])

    def test_a_path_line_that_runs_brew_by_name(self):
        path = self.rc(".zprofile", 'export PATH="$(brew --prefix)/opt/python/libexec/bin:$PATH"\n'
                                    f"export PATH={self.brew_prefix}/bin:$PATH\n")
        got = [(x.kind, x.position, x.brew, x.instance_prefixes) for x in self.records(self.analyse(), path)]
        self.assertEqual(got, [("assign", "prepend", "", []), ("assign", "prepend", None, [self.brew_prefix])])

    def test_a_shellenv_line_of_a_prefix_that_is_gone(self):
        gone = "/nonexistent-bpu/usr/local"
        inst = model.Instance(model.Manager.BREW, gone, (0, 9), (gone,), gone + "/bin/brew", "4.0", "x86_64",
                              model.Usability.MISSING_BINARY, None, False, None, gone + "/Homebrew", None, None, None)
        path = self.rc(".bashrc", f'eval "$({gone}/bin/brew shellenv)"\nexport PATH="{gone}/opt/x/bin:$PATH"\n')
        a = self.analyse(instances=[self.brew, inst])
        self.assertEqual([x.instance_prefixes for x in self.records(a, path)], [[gone], [gone]])

    def test_dyld_and_build_exports(self):
        path = self.rc(".zshrc", "\n".join([
            f"export DYLD_LIBRARY_PATH={self.ports_prefix}/lib:$DYLD_LIBRARY_PATH",
            f"export DYLD_FALLBACK_LIBRARY_PATH={self.brew_prefix}/lib",
            f'export LDFLAGS="-L{self.brew_prefix}/opt/openssl@3/lib -Wl,-rpath,{self.ports_prefix}/lib $LDFLAGS"',
            f'export CPPFLAGS="-I{self.brew_prefix}/opt/openssl@3/include"',
            f'export PKG_CONFIG_PATH="{self.brew_prefix}/opt/openssl@3/lib/pkgconfig:$PKG_CONFIG_PATH"',
            "export PYTHONPATH=/elsewhere/lib/python",
        ]) + "\n")
        got = [(x.kind, x.var, x.self_ref, x.position, x.instance_prefixes) for x in self.records(self.analyse(), path)]
        self.assertEqual(got, [
            ("dyld", "DYLD_LIBRARY_PATH", True, "prepend", [self.ports_prefix]),
            ("dyld", "DYLD_FALLBACK_LIBRARY_PATH", False, "reset", [self.brew_prefix]),
            ("build", "LDFLAGS", True, "", sorted([self.brew_prefix, self.ports_prefix])),
            ("build", "CPPFLAGS", False, "", [self.brew_prefix]),
            ("build", "PKG_CONFIG_PATH", True, "prepend", [self.brew_prefix]),
            ("build", "PYTHONPATH", False, "reset", [])])

    def test_path_assignment_positions(self):
        path = self.rc(".zshrc", "\n".join([
            f"export PATH=/usr/bin:/bin:{self.brew_prefix}/bin",
            f"path=({self.brew_prefix}/bin $path)",
            f"PATH+=:{self.ports_prefix}/bin",
            f'export PATH="$PATH:{self.ports_prefix}/sbin"',
            f"PATH={self.brew_prefix}/sbin:$PATH:{self.ports_prefix}/bin; export PATH",
            "typeset -U path PATH",
            "export PATH",
        ]) + "\n")
        got = [(x.lineno, x.position, x.self_ref) for x in self.records(self.analyse(), path)]
        self.assertEqual(got, [(1, "reset", False), (2, "prepend", True), (3, "append", True), (4, "append", True),
                               (5, "both", True)])
        bash = self.rc(".bashrc", f"path=({self.brew_prefix}/bin $path)\n")     # only zsh ties path to PATH
        self.assertEqual([(x.kind, x.command) for x in self.records(self.analyse(), bash)], [("source", "other")])

    def test_manpath_is_tied_to_its_variable_in_zsh_alone(self):
        zshrc = self.rc(".zshrc", f"manpath=({self.ports_prefix}/share/man $manpath)\n")
        tcshrc = self.rc(".tcshrc", f"set manpath = ( {self.ports_prefix}/share/man $manpath )\n")
        a = self.analyse()
        self.assertEqual([(x.kind, x.var, x.position) for x in self.records(a, zshrc)],
                         [("assign", "MANPATH", "prepend")])
        self.assertEqual([x for x in self.records(a, tcshrc) if x.var == "MANPATH"], [])

    def test_tcsh_and_fish_forms(self):
        tcshrc = self.rc(".tcshrc", "\n".join([
            f'setenv PATH "{self.ports_prefix}/bin:{self.ports_prefix}/sbin:$PATH"',
            f"set path = ( {self.brew_prefix}/bin $path )",
            f"setenv MANPATH {self.ports_prefix}/share/man:$MANPATH",
        ]) + "\n")
        xdg = self.path("xdg")
        fish = os.path.join(xdg, "fish", "config.fish")
        os.makedirs(os.path.dirname(fish))
        with open(fish, "w", encoding="utf-8") as fh:
            fh.write("\n".join([
                f"set -gx PATH {self.brew_prefix}/bin $PATH",
                f"fish_add_path {self.ports_prefix}/bin",
                "fish_add_path -a /x/bin",
                f"set -U fish_user_paths {self.brew_prefix}/sbin $fish_user_paths",
                f"set -gx DYLD_LIBRARY_PATH {self.ports_prefix}/lib",
                f"if test -f {self.ports_prefix}/share/fish/x.fish; source {self.ports_prefix}/share/fish/x.fish; end",
                "set -e PATH",
            ]) + "\n")
        a = self.analyse({"PATH": "/usr/bin", "XDG_CONFIG_HOME": xdg})
        self.assertIn(fish, [f.path for f in a.files if f.exists])
        self.assertEqual([(x.kind, x.var, x.position, x.instance_prefixes) for x in self.records(a, tcshrc)], [
            ("assign", "PATH", "prepend", [self.ports_prefix]), ("assign", "PATH", "prepend", [self.brew_prefix]),
            ("assign", "MANPATH", "prepend", [self.ports_prefix])])
        got = [(x.kind, x.var, x.position, x.compound, x.instance_prefixes) for x in self.records(a, fish)]
        self.assertEqual(got, [
            ("assign", "PATH", "prepend", False, [self.brew_prefix]),
            ("assign", "PATH", "prepend", False, [self.ports_prefix]), ("assign", "PATH", "append", False, []),
            ("assign", "fish_user_paths", "prepend", False, [self.brew_prefix]),
            ("dyld", "DYLD_LIBRARY_PATH", "reset", False, [self.ports_prefix]),
            ("source", None, "", True, [self.ports_prefix])])

    def test_compound_continuations_and_here_documents(self):
        path = self.rc(".bashrc", "\n".join([
            f"export PATH={self.ports_prefix}/bin:\\",
            f"{self.brew_prefix}/bin:$PATH",
            "cat <<EOF >> /tmp/notes",
            f"source {self.ports_prefix}/etc/inside-heredoc",
            "EOF",
            f'case "$TERM" in xterm*) . {self.ports_prefix}/etc/xterm.sh ;; esac',
            "myfunc() { . %s/etc/fn.sh; }" % self.ports_prefix,
            f". {self.ports_prefix}/etc/after.sh",
        ]) + "\n")
        recs = self.records(self.analyse(), path)
        by_line: dict[int, list[bool]] = {}
        for rec in recs:
            by_line.setdefault(rec.lineno, []).append(rec.compound)
        self.assertEqual(by_line, {1: [True], 2: [True], 4: [True], 6: [True], 7: [True], 8: [False]})

    def test_every_line_of_a_construct_spread_over_lines_is_compound(self):
        brew, ports = self.brew_prefix, self.ports_prefix
        zshrc = self.rc(".zshrc", "\n".join([
            'if [ "$(uname -m)" = arm64 ]; then',
            f'  eval "$({brew}/bin/brew shellenv)"',
            "else",
            f'  export PATH="{ports}/bin:$PATH"',
            "fi",
            "arm() {",
            f"  source {ports}/etc/arm.sh",
            "}",
            "path=(",
            f"  {ports}/bin",
            "  $path",
            ")",
            f'for d in {ports}/bin {ports}/sbin; do PATH="$d:$PATH"; done',
            f"export PATH={ports}/bin:\\",
            "$PATH",
            'case "$TERM" in',
            f"  xterm*) source {ports}/etc/xterm.sh ;;",
            "esac",
            f"source {ports}/etc/after.sh",
            "PROMPT='%n",
            f"{ports}/bin # %# '",
            f"source {ports}/etc/last.sh",
        ]) + "\n")
        fish = self.rc(".config/fish/config.fish", "\n".join([
            "if test (uname -m) = arm64",
            f"    eval ({brew}/bin/brew shellenv)",
            f"else if test -d {ports}/bin",
            f"    set -gx PATH {ports}/bin $PATH",
            "else",
            f"    fish_add_path {ports}/sbin",
            "end",
            "function brewx",
            f"    {brew}/bin/brew $argv",
            "end",
            f"set -gx PATH {ports}/sbin $PATH",
        ]) + "\n")
        tcshrc = self.rc(".tcshrc", "\n".join([
            "if ( `uname -m` == arm64 ) then",
            f"    eval `{brew}/bin/brew shellenv`",
            f"else if ( -d {ports}/bin ) then",
            f"    setenv PATH {ports}/bin:$PATH",
            "else",
            f"    set path = ( {ports}/sbin $path )",
            "endif",
            f"foreach d ( {ports}/bin {ports}/sbin )",
            "    setenv PATH ${d}:$PATH",
            "end",
            "switch ( $TERM )",
            "case xterm*:",
            f"    source {ports}/etc/xterm.csh",
            "    breaksw",
            "endsw",
            f"if ( -d {ports}/bin ) setenv PATH {ports}/bin:$PATH",
            f"setenv MANPATH {ports}/share/man:$MANPATH",
        ]) + "\n")
        a = self.analyse()
        compound = {path: {x.lineno: x.compound for x in self.records(a, path)} for path in (zshrc, fish, tcshrc)}
        self.assertEqual(compound, {
            zshrc: {2: True, 4: True, 7: True, 9: True, 10: True, 13: True, 14: True, 17: True, 19: False, 21: True,
                    22: False},
            fish: {2: True, 3: True, 4: True, 6: True, 9: True, 11: False},
            tcshrc: {2: True, 3: True, 4: True, 6: True, 8: True, 9: True, 13: True, 16: True, 17: False}})
        nested = {path: {x.lineno for x in self.records(a, path) if x.nested} for path in (zshrc, fish, tcshrc)}
        self.assertEqual(nested, {zshrc: {2, 4, 7, 9, 10, 17, 21}, fish: {2, 3, 4, 6, 9},
                                  tcshrc: {2, 3, 4, 6, 8, 9, 13}})

    def test_zsh_short_forms_close_where_their_body_ends(self):
        ports = self.ports_prefix
        zshrc = self.rc(".zshrc", "\n".join([
            f"for f ({ports}/etc/zsh.d/*.zsh(N)) source $f",
            f"source {ports}/etc/a.sh",
            f"for f in {ports}/etc/b.zsh(N) {ports}/etc/c.zsh(N); source $f",
            f"source {ports}/etc/d.sh",
            f"if [[ -d {ports}/bin ]] {{",
            f"  export PATH={ports}/bin:$PATH",
            "} else {",
            f"  source {ports}/etc/e.sh",
            "}",
            f"source {ports}/etc/f.sh",
            f"if [[ -f {ports}/etc/g.sh ]] source {ports}/etc/g.sh",
            f"while [[ -z $n ]] {{ source {ports}/etc/h.sh; n=1 }}",
            f"repeat 1 source {ports}/etc/i.sh",
            "for f in 1",
            f"  source {ports}/etc/j.sh",
            f"source {ports}/etc/k.sh",
            "repeat() { command repeat-bpu \"$@\"; }",
            f"source {ports}/etc/l.sh",
            f"while true; {{ source {ports}/etc/m.sh }}",
            f"source {ports}/etc/n.sh",
        ]) + "\n")
        recs = self.records(self.analyse(), zshrc)
        self.assertEqual({x.lineno: x.compound for x in recs}, {
            1: True, 2: False, 3: True, 4: False, 5: True, 6: True, 8: True, 10: False, 11: True, 12: True, 13: True,
            15: True, 16: False, 18: False, 19: True, 20: True})
        self.assertEqual({x.lineno for x in recs if x.nested}, {5, 6, 8, 15, 19, 20})


class FilesTest(ShellTest):
    """Tests of the files the analysis reads: `/etc/paths`, the read order, symlinked and unreadable files"""

    def test_etc_paths(self):
        self.touch(os.path.join(self.etc, "paths"), fixture("etc-paths.txt", BREW=self.brew_prefix).encode())
        self.touch(os.path.join(self.etc, "paths.d", "homebrew"), (self.brew_prefix + "/bin\n").encode())
        self.touch(os.path.join(self.etc, "paths.d", "40-XQuartz"), b"/opt/X11/bin\n\n")
        os.makedirs(os.path.join(self.etc, "paths.d", "subdir"))
        got = [(os.path.basename(x.file), x.lineno, x.entry.text, x.entry.instance_prefix, x.stock)
               for x in self.analyse().etc_paths]
        self.assertEqual(got, [
            ("paths", 1, "/usr/local/bin", None, True), ("paths", 2, "/System/Cryptexes/App/usr/bin", None, False),
            ("paths", 3, "/usr/bin", None, False), ("paths", 4, "/bin", None, False),
            ("paths", 5, "/usr/sbin", None, False),
            ("paths", 6, "/sbin", None, False), ("paths", 7, self.brew_prefix + "/bin", self.brew_prefix, False),
            ("40-XQuartz", 1, "/opt/X11/bin", None, False),
            ("homebrew", 1, self.brew_prefix + "/bin", self.brew_prefix, False)])

    def test_read_order(self):
        self.rc(".bash_profile", "[ -r ~/.bashrc ] && . ~/.bashrc\n")
        self.rc(".bashrc", "alias ll='ls -l'\n")
        self.rc(".profile", "export PATH=$HOME/bin:$PATH\n")
        self.touch(os.path.join(self.etc, "profile"),
                   (f'[ -r "{self.etc}/bashrc" ] && . "{self.etc}/bashrc"\n').encode())
        self.touch(os.path.join(self.etc, "bashrc"), b"PS1='$ '\n")
        a = self.analyse(login="/bin/bash")
        self.assertEqual(a.read_order, [os.path.join(self.etc, "profile"), os.path.join(self.etc, "bashrc"),
                                        os.path.join(self.home, ".bash_profile"), os.path.join(self.home, ".bashrc")])
        zd = os.path.join(self.home, "zd")
        self.rc(".zshenv", "export ZDOTDIR=$HOME/zd\n")
        self.rc("zd/.zprofile", "")
        self.rc("zd/.zshrc", "")
        self.touch(os.path.join(self.etc, "zprofile"), b"eval `/usr/libexec/path_helper -s`\n")
        self.assertEqual(sh.read_order("zsh", self.home, zd, {}, self.etc), [
            os.path.join(self.home, ".zshenv"), os.path.join(self.etc, "zprofile"), os.path.join(zd, ".zprofile"),
            os.path.join(zd, ".zshrc")])
        self.assertEqual(sh.read_order("sh", self.home, None, {}, self.etc),
                         [os.path.join(self.etc, "profile"), os.path.join(self.home, ".profile")])
        self.rc(".cshrc", "")
        self.assertEqual(sh.read_order("tcsh", self.home, None, {}, self.etc), [os.path.join(self.home, ".cshrc")])
        self.rc(".tcshrc", "")
        self.assertEqual(sh.read_order("csh", self.home, None, {}, self.etc), [os.path.join(self.home, ".tcshrc")])
        self.assertEqual(sh.read_order("ksh", self.home, None, {}, self.etc), [])

    def test_symlinked_and_unreadable_rc_files(self):
        real = self.rc("dotfiles/zshrc", f"export PATH={self.brew_prefix}/bin:$PATH\n")
        os.symlink(real, os.path.join(self.home, ".zshrc"))
        locked = self.rc(".bashrc", f"export PATH={self.ports_prefix}/bin:$PATH\n")
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o644)
        a = self.analyse()
        files = {f.path: f for f in a.files}
        zshrc = files[os.path.join(self.home, ".zshrc")]
        self.assertEqual((zshrc.exists, zshrc.realpath, zshrc.owner_uid), (True, real, os.getuid()))
        self.assertEqual(len(self.records(a, os.path.join(self.home, ".zshrc"))), 1)
        if os.geteuid() != 0:
            self.assertIn("PermissionError", files[locked].error)
        self.assertFalse(files[os.path.join(self.home, ".tcshrc")].exists)


class LiveTest(ShellTest):
    """Tests of the live environment: repeated and missing entries, shadowed commands and the GUI PATH"""

    def test_live_duplicates_dead_entries_and_shadowing(self):
        provided = ((self.brew, ("bin/python3", "bin/jq")), (self.ports, ("bin/python3", "sbin/jq", "bin/port")))
        for inst, names in provided:
            for name in names:
                self.touch(os.path.join(inst.prefix, *name.split("/")), b"#!/bin/sh\n", 0o755)
        self.touch(os.path.join(self.ports_prefix, "bin", "notexec"), b"x", 0o644)
        self.touch(os.path.join(self.brew_prefix, "bin", "notexec"), b"x", 0o644)
        environ = {"PATH": f"{self.ports_prefix}/bin:{self.brew_prefix}/bin:/usr/bin:{self.ports_prefix}/bin:"
                           "/nonexistent-bpu/bin",
                   "MANPATH": f":{self.ports_prefix}/share/man", "DYLD_LIBRARY_PATH": f"{self.ports_prefix}/lib",
                   "LDFLAGS": f"-L{self.brew_prefix}/lib"}
        a = self.analyse(environ)
        self.assertEqual([(e.text, e.instance_prefix) for e in a.live["PATH"]], [
            (self.ports_prefix + "/bin", self.ports_prefix), (self.brew_prefix + "/bin", self.brew_prefix),
            ("/usr/bin", None), (self.ports_prefix + "/bin", self.ports_prefix), ("/nonexistent-bpu/bin", None)])
        self.assertFalse(a.live["PATH"][-1].exists)
        self.assertEqual(a.live_duplicates, {"PATH": [self.ports_prefix + "/bin"]})
        self.assertEqual([e.text for e in a.live["MANPATH"]], [self.ports_prefix + "/share/man"])
        self.assertEqual([e.instance_prefix for e in a.live["DYLD_LIBRARY_PATH"]], [self.ports_prefix])
        self.assertEqual([e.text for e in a.live["LDFLAGS"]], [self.brew_prefix + "/lib"])
        got = [(x.command, x.prefixes, x.winner, x.winner_prefix) for x in a.shadowed]
        self.assertEqual(got, [
            ("jq", [self.brew_prefix, self.ports_prefix], os.path.join(self.brew_prefix, "bin", "jq"),
             self.brew_prefix),
            ("python3", [self.brew_prefix, self.ports_prefix], os.path.join(self.ports_prefix, "bin", "python3"),
             self.ports_prefix)])
        self.assertEqual(sh.path_index(a.live["PATH"], self.brew_prefix + "/bin"), 1)
        self.assertIsNone(sh.path_index(a.live["PATH"], self.brew_prefix + "/sbin"))

    def test_gui_path(self):
        responses = {(sh.LAUNCHCTL, "getenv", "PATH"): r.FakeResponse(stdout=self.ports_prefix + "/bin:/usr/bin\n")}
        a = self.analyse(responses=responses)
        self.assertEqual([(e.text, e.instance_prefix) for e in a.gui_path],
                         [(self.ports_prefix + "/bin", self.ports_prefix), ("/usr/bin", None)])
        self.assertIsNone(self.analyse().gui_path)

    def test_round_trip_through_scan_json(self):
        self.rc(".zprofile", fixture("zprofile-macports.txt", PORTS=self.ports_prefix, BREW=self.brew_prefix))
        a = self.analyse({"PATH": self.brew_prefix + "/bin:/usr/bin"}, login="/bin/zsh")
        back = model.from_dict(sh.ShellAnalysis, json.loads(model.to_json(a)))
        self.assertEqual(back, a)


class LoginShellTest(ShellTest):
    """Tests of the login shell: its prefix through its realpath, the probe and its fallback, the PATH probe"""

    def test_login_shell_under_a_prefix_through_realpath(self):
        ul = self.usr_local()
        bash = self.touch(os.path.join(ul.prefix, "Cellar", "bash", "5.2", "bin", "bash"), b"", 0o755)
        os.makedirs(os.path.join(ul.prefix, "bin"))
        os.symlink(bash, os.path.join(ul.prefix, "bin", "bash"))
        a = self.analyse(login=os.path.join(ul.prefix, "bin", "bash"), instances=[self.brew, ul])
        self.assertEqual((a.login_shell_prefix, a.login_shell_realpath), (ul.prefix, bash))
        self.assertIsNone(self.analyse(login="/bin/zsh").login_shell_prefix)

    def test_login_shell_probe_and_fallback(self):
        argv = (sh.DSCL, ".", "-read", "/Users/alice", "UserShell")
        fake = self.runner({argv: r.FakeResponse(stdout="UserShell: /opt/homebrew/bin/fish\n")})
        self.assertEqual(sh.login_shell(fake, "alice"), "/opt/homebrew/bin/fish")
        failing = self.runner({}, default=r.FakeResponse(exit=184, stderr="eDSRecordNotFound"))
        with mock.patch.object(sh.pwd, "getpwnam", return_value=mock.Mock(pw_shell="/bin/bash")):
            self.assertEqual(sh.login_shell(failing, "alice"), "/bin/bash")
        with mock.patch.object(sh.pwd, "getpwnam", side_effect=KeyError("alice")):
            self.assertIsNone(sh.login_shell(failing, "alice"))
        wrapped = self.runner({argv: r.FakeResponse(stdout="UserShell:\n /bin/zsh\n")})
        self.assertEqual(sh.login_shell(wrapped, "alice"), "/bin/zsh")
        no_shell = self.runner({argv: r.FakeResponse(stdout="RealName: Alice\n")})
        with mock.patch.object(sh.pwd, "getpwnam", return_value=mock.Mock(pw_shell="/bin/bash")):
            self.assertEqual(sh.login_shell(no_shell, "alice"), "/bin/bash")

    def test_login_path_helpers(self):
        self.assertEqual(sh.login_path_argv("/bin/zsh"), ["/bin/zsh", "-l", "-i", "-c", "echo $PATH"])
        self.assertEqual(sh.login_path_argv("/bin/tcsh"), ["/bin/tcsh", "-c", "echo $PATH"])
        out = "Last login: Thu\n\x1b]0;title\x07\x1b[1m/opt/homebrew/bin:/usr/bin:/bin\x1b[0m\n"
        self.assertEqual(sh.parse_login_path(out, "/bin/zsh"), ["/opt/homebrew/bin", "/usr/bin", "/bin"])
        self.assertEqual(sh.parse_login_path("/opt/homebrew/bin /usr/bin /bin\n", "/opt/homebrew/bin/fish"),
                         ["/opt/homebrew/bin", "/usr/bin", "/bin"])
        self.assertIsNone(sh.parse_login_path("nothing here\n", "/bin/zsh"))


class SyntaxCheckTest(ShellTest):
    """Tests of the syntax check of a rewritten shell file"""

    def test_each_shell_parser_without_startup_files(self):
        seen = []

        def respond(key):
            seen.append(key)
            with open(key[-1], encoding="utf-8") as fh:
                broken = "BROKEN" in fh.read()
            return r.FakeResponse(exit=2 if broken else 0, stderr="syntax error\n" if broken else "")
        fake = self.runner(default=respond)
        self.assertTrue(sh.syntax_check(fake, "zsh", "export PATH=/x:$PATH\n", tmp_dir=self.tmp))
        self.assertFalse(sh.syntax_check(fake, "bash", "if BROKEN\n", tmp_dir=self.tmp, subject="/Users/alice/.bashrc"))
        self.assertTrue(sh.syntax_check(fake, "sh", "true\n", tmp_dir=self.tmp))
        self.assertTrue(sh.syntax_check(fake, "csh", "setenv PATH /x\n", tmp_dir=self.tmp))
        self.assertIsNone(sh.syntax_check(fake, "fish", "set -gx PATH /x $PATH\n", tmp_dir=self.tmp))
        self.assertTrue(sh.syntax_check(fake, "fish", "set -gx PATH /x\n", fish="/opt/homebrew/bin/fish",
                                        tmp_dir=self.tmp))
        self.assertIsNone(sh.syntax_check(fake, "ksh", "x\n", tmp_dir=self.tmp))
        self.assertEqual([key[:-1] for key in seen], [
            ("/bin/zsh", "-f", "-n"), ("/bin/bash", "-n"), ("/bin/sh", "-n"), ("/bin/tcsh", "-f", "-n"),
            ("/opt/homebrew/bin/fish", "--no-config", "--no-execute")])
        self.assertFalse([n for n in os.listdir(self.tmp) if n.startswith("brew-ports-syntax-")])
        self.assertNotIn("BASH_ENV", r.profile_env("neutral", {"BASH_ENV": "/x", "HOME": "/h"}))
        missing = self.runner(default=r.FakeResponse(exit=127, stderr="/bin/zsh: No such file or directory\n"))
        self.assertIsNone(sh.syntax_check(missing, "zsh", "true\n", tmp_dir=self.tmp))


class WordsTest(unittest.TestCase):
    """Tests of the shell word reader, the splitters, the comment stripper and the expander"""

    def test_reader_and_expander(self):
        self.assertEqual(sh.read_word('"a b"c\'d e\' rest', 0), ("a bcd e", 11))
        self.assertEqual(sh.read_word('"$(brew --prefix)/bin":$PATH;', 0)[0], "$(brew --prefix)/bin:$PATH")
        self.assertEqual(sh.split_colon("${X:-/a}/b:/c:$(cmd a:b)"), ["${X:-/a}/b", "/c", "$(cmd a:b)"])
        self.assertEqual(sh.split_words(" /a  '$b c' "), ["/a", "$b c"])
        self.assertEqual(sh.strip_comment('echo "#not" x # comment'), 'echo "#not" x ')
        self.assertEqual(sh.strip_comment("echo ${#x} $# a#b"), "echo ${#x} $# a#b")
        env = {"HOME": "/Users/alice", "X": "/x"}
        self.assertEqual(sh.expand("~/bin", env), "/Users/alice/bin")
        self.assertEqual(sh.expand("${X}/bin:$HOME", env), "/x/bin:/Users/alice")
        self.assertEqual(sh.expand("${NOPE:-$HOME/.config}/zsh", env), "/Users/alice/.config/zsh")
        self.assertIsNone(sh.expand("$NOPE/bin", env))
        self.assertIsNone(sh.expand("$(brew --prefix)/bin", env))
        self.assertIsNone(sh.expand("~bob/bin", env))


if __name__ == "__main__":
    unittest.main()

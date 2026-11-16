"""PrefixIndex (its identity and text rules) and the `scan` text of the environment analysis

The helpers at the top are shared by the other `test_env_*` modules.
"""

import io
import os
import unittest

from brew_ports import env, model, runner as r, system
from brew_ports.report import Console
from tests.unit.helpers import TempDirTest, make_instance

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "env")
USR_LOCAL_ROOTS = ("Cellar", "Caskroom", "Homebrew", "opt", os.path.join("var", "homebrew"))


def fixture(name, **tokens):
    """Read a fixture file with its `<TOKEN>` placeholders filled in

    @param name    the file's name in `fixtures/env`
    @param tokens  the text of each placeholder, by its name
    @returns       the file's text
    """
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        text = fh.read()
    for key, value in tokens.items():
        text = text.replace(f"<{key}>", value)
    return text


class QuietConsole(Console):
    """A console that writes into memory, so the tests print nothing"""

    def __init__(self):
        """Send both streams into memory"""
        super().__init__(stream=io.StringIO(), err=io.StringIO())


class EnvTest(TempDirTest):
    """The base of the `test_env_*` tests: temporary prefixes and files, and a FakeRunner"""

    def mkdirs(self, *paths):
        """Make directories with their parents

        @param paths  the directories
        """
        for path in paths:
            os.makedirs(path, exist_ok=True)

    def touch(self, path, data=b"", mode=None):
        """Write a file with its parent directories

        @param path  the file
        @param data  its content
        @param mode  its permission bits; None keeps the default
        @returns     the path
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        if mode is not None:
            os.chmod(path, mode)
        return path

    def instance(self, manager=model.Manager.BREW, name="opt/homebrew", roots=None):
        """Return an instance at a temporary prefix, made with its owned roots

        @param manager  Homebrew or MacPorts
        @param name     the prefix below the temporary directory, with `/` separators
        @param roots    the owned roots, relative to the prefix; None for the prefix itself
        @returns        the instance, as `make_instance` builds it
        """
        prefix = self.path(*name.split("/"))
        os.makedirs(prefix, exist_ok=True)
        if roots is None:
            owned: tuple[str, ...] = (prefix,)
        else:
            owned = tuple(os.path.join(prefix, root) for root in roots)
            self.mkdirs(*owned)
        return make_instance(manager, prefix, identity=system.identity(prefix), spellings=(prefix,), owned_roots=owned)

    def usr_local(self, name="usr/local"):
        """Return a Homebrew instance at a temporary `/usr/local` that owns only Homebrew's roots there

        @param name  the prefix below the temporary directory
        @returns     the instance
        """
        return self.instance(model.Manager.BREW, name, roots=USR_LOCAL_ROOTS)

    def runner(self, responses=None, default=None):
        """Return a quiet fake runner with an empty environment

        @param responses  the canned responses, by argv; None for none
        @param default    the responder for a command not listed; None refuses it
        @returns          the runner
        """
        return r.FakeRunner(responses=responses or {}, default=default, console=QuietConsole(), environ={},
                            out_dir=self.path("runner-out"))


class PrefixIndexTest(EnvTest):
    """Tests of PrefixIndex: identity through symlinks, the text rule for a gone prefix, the longest root"""

    def test_identity_through_symlinks_and_the_usr_local_roots(self):
        brew = self.instance()
        ul = self.usr_local()
        self.mkdirs(os.path.join(ul.prefix, "go", "bin"), os.path.join(ul.prefix, "bin"),
                    os.path.join(ul.prefix, "Cellar", "wget", "1.0", "bin"))
        os.symlink(os.path.join(ul.prefix, "Cellar", "wget", "1.0", "bin", "wget"),
                   os.path.join(ul.prefix, "bin", "wget"))
        alias = self.path("alias")
        os.symlink(brew.prefix, alias)
        index = env.PrefixIndex([brew, ul])
        self.assertIs(index.owner(os.path.join(brew.prefix, "Cellar", "x", "1.0", "bin", "x")), brew)
        self.assertIs(index.owner(os.path.join(alias, "bin", "x")), brew)
        self.assertIs(index.owner(os.path.join(ul.prefix, "Cellar", "wget")), ul)
        self.assertIs(index.owner(os.path.join(ul.prefix, "bin", "wget")), ul)       # a link into the Cellar
        self.assertIsNone(index.owner(os.path.join(ul.prefix, "go", "bin", "go")))   # Go's own tree
        self.assertIsNone(index.owner(os.path.join(ul.prefix, "bin")))
        self.assertIsNone(index.owner(self.path("elsewhere")))
        self.assertIsNone(index.owner("relative/path"))

    def test_text_rule_for_a_prefix_that_is_gone(self):
        gone = "/nonexistent-bpu-test/opt/local"
        ports = make_instance(model.Manager.PORTS, gone, identity=(0, 0), spellings=(gone,), owned_roots=(gone,))
        ul_gone = "/nonexistent-bpu-test/usr/local"
        ul = make_instance(model.Manager.BREW, ul_gone, identity=(0, 1), spellings=(ul_gone,),
                           owned_roots=tuple(os.path.join(ul_gone, root) for root in USR_LOCAL_ROOTS))
        index = env.PrefixIndex([ports, ul])
        self.assertIs(index.owner(gone + "/bin"), ports)
        self.assertIs(index.owner("/System/Volumes/Data" + gone + "/sbin/port"), ports)
        self.assertIsNone(index.owner(gone + "-old/bin"))
        self.assertIs(index.owner(ul_gone + "/opt/coreutils/libexec/gnubin"), ul)
        self.assertIsNone(index.owner(ul_gone + "/bin"))        # /usr/local/bin is not Homebrew's own
        self.assertEqual(index.prefix_of(gone + "/lib/x.dylib"), gone)

    def test_the_longest_root_wins(self):
        outer = self.instance(model.Manager.PORTS, "opt/local")
        inner = self.instance(model.Manager.BREW, "opt/local/homebrew")
        index = env.PrefixIndex([outer, inner])
        self.assertIs(index.owner(os.path.join(inner.prefix, "bin", "x")), inner)
        self.assertIs(index.owner(os.path.join(outer.prefix, "bin", "x")), outer)
        self.assertIs(index.by_text(os.path.join(inner.prefix, "bin")), inner)


class RenderTest(EnvTest):
    """Tests of the `scan` text of the environment analysis"""

    def test_scan_text_has_every_section(self):
        environment = {
            "login_shell": "/bin/zsh", "login_shell_prefix": None,
            "live": {"PATH": [{"text": "/opt/homebrew/bin", "instance_prefix": "/opt/homebrew", "exists": True},
                              {"text": "/gone", "instance_prefix": None, "exists": False}]},
            "live_duplicates": {}, "records": [{"file": "~/.zprofile", "lineno": 3, "kind": "shellenv",
                                                "instance_prefixes": ["/opt/homebrew"]}],
            "etc_paths": [], "gui_path": None,
            "shadowed": [{"command": "python3", "winner": "/opt/local/bin/python3",
                          "prefixes": ["/opt/homebrew", "/opt/local"]}],
        }
        linkage = {"binaries": {"/opt/homebrew/Cellar/a/1/bin/a": {
            "package": "/opt/homebrew|formula|a",
            "references": [{"name": "/opt/local/lib/libz.1.dylib", "class": "other"}]}}}
        extras = {"python": [{"version": "3.12", "instance_prefix": None, "dists": [{"name": "x"}]}],
                  "npm": [{"instance_prefix": "/opt/homebrew", "name": "typescript"}]}
        svc = model.Service("sh.brew.redis", "/p.plist", "user", "gui/501", True, True, 7, 20, True, [], "redis",
                            "formula", "/opt/homebrew")
        text = "\n".join(env.render(environment, linkage, extras, [svc]))
        for needle in ("PATH analysis", "Shadowed commands", "python3", "Cross-prefix linkage", "libz.1.dylib",
                       "Interpreter extras", "python3.12", "npm globals", "Services", "sh.brew.redis", "missing"):
            self.assertIn(needle, text)

    def test_empty_sections(self):
        text = "\n".join(env.render({}, {}, {}))
        self.assertIn("no other, usrlocal or missing references in 0 binaries", text)


if __name__ == "__main__":
    unittest.main()

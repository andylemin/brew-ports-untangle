"""Tests of redaction, the console and the text table"""

import io
import json
import os
import unittest

from brew_ports import model, report
from tests.unit.helpers import TempDirTest, make_instance, write_file


class RedactionTest(unittest.TestCase):
    """Tests of the home directory and login name redaction"""

    def setUp(self):
        self.red = report.Redactor(home="/Users/alice", user="alice")

    def test_json_value_with_escaped_newline(self):
        text = json.dumps({"path": "/Users/alice\n"})
        self.assertEqual(self.red(text), json.dumps({"path": "~\n"}))

    def test_path_entry_and_command_line(self):
        self.assertEqual(self.red("PATH=/Users/alice/bin:/usr/bin"), "PATH=~/bin:/usr/bin")
        self.assertEqual(self.red("cp /Users/alice/.zshrc >/tmp/x"), "cp ~/.zshrc >/tmp/x")
        self.assertEqual(self.red("open /Users/alice>"), "open ~>")

    def test_backup_name_form(self):
        self.assertEqual(self.red("backup/%Users%alice%.zshrc"), "backup/~%.zshrc")

    def test_file_uri(self):
        self.assertEqual(self.red("file:///Users/alice/x"), "file://~/x")

    def test_longer_names_are_left_alone(self):
        self.assertEqual(self.red("/Users/alice-old/x"), "/Users/alice-old/x")
        self.assertEqual(self.red("/Users/alicex/x"), "/Users/alicex/x")

    def test_login_name(self):
        self.assertEqual(self.red("USER=alice LOGNAME=alice"), "USER=<user> LOGNAME=<user>")
        self.assertEqual(self.red("/Users/alice2/x"), "/Users/alice2/x")

    def test_home_outside_users(self):
        red = report.Redactor(home="/var/home/bob", user="bob")
        self.assertEqual(red("x /var/home/bob/y"), "x ~/y")


class ConsoleTest(unittest.TestCase):
    """Tests of the console's levels, JSON mode and redaction, and of the text table"""

    def test_quiet_and_silenced(self):
        out, err = io.StringIO(), io.StringIO()
        c = report.Console(stream=out, err=err, quiet=True)
        c.info("hidden")
        c.out("shown")
        c.silenced = True
        c.out("after hangup")
        c.warn("after hangup")
        self.assertEqual(out.getvalue(), "shown\n")
        self.assertEqual(err.getvalue(), "")

    def test_json_mode_keeps_stdout_for_the_json(self):
        out, err = io.StringIO(), io.StringIO()
        c = report.Console(stream=out, err=err)
        c.json_mode = True
        c.info("doctor: reusing the scan")
        c.json({"a": 1})
        self.assertEqual(json.loads(out.getvalue()), {"a": 1})
        self.assertIn("reusing the scan", err.getvalue())

    def test_redacted_output(self):
        out = io.StringIO()
        c = report.Console(stream=out, err=io.StringIO(), redact=True,
                           redactor=report.Redactor(home="/Users/alice", user="alice"))
        c.out("/Users/alice/x")
        self.assertEqual(out.getvalue(), "~/x\n")

    def test_table(self):
        lines = report.table([("a", 1), ("bbb", 22)], ["name", "n"])
        self.assertEqual(lines[0], "name  n")
        self.assertEqual(lines[2], "a     1")

    def test_an_error_carries_the_tool_name_even_when_quiet(self):
        err = io.StringIO()
        report.Console(stream=io.StringIO(), err=err, quiet=True).error("no plan was found")
        self.assertEqual(err.getvalue(), "brew-ports: no plan was found\n")


class WordsTest(TempDirTest):
    """Tests of the names, counts, lists and commands as the reader meets them"""

    def test_an_installation_is_named_in_full(self):
        ports = make_instance(model.Manager.PORTS, "/opt/local", version="2.10.5")
        intel = make_instance(model.Manager.BREW, "/usr/local", version="4.6.0", arch="x86_64")
        self.assertEqual(report.place(ports), "MacPorts 2.10.5 at /opt/local (Apple Silicon)")
        self.assertEqual(report.place(intel), "Homebrew 4.6.0 at /usr/local (Intel)")
        self.assertEqual(report.at(intel), "Homebrew at /usr/local")

    def test_an_installation_whose_command_cannot_run_says_so(self):
        broken = make_instance(model.Manager.PORTS, "/opt/local", version=None, arch=None, drivable=False,
                               usability=model.Usability.NO_REGISTRY)
        self.assertEqual(report.place(broken), "MacPorts at /opt/local (its `port` command cannot run)")

    def test_counts_and_capped_lists(self):
        self.assertEqual(report.counted(1, "port"), "1 port")
        self.assertEqual(report.counted(1240, "file"), "1,240 files")
        self.assertEqual(report.counted(2, "entry", "entries"), "2 entries")
        self.assertEqual(report.some(["a", "b"]), "a, b")
        self.assertEqual(report.some([str(n) for n in range(11)]), "0, 1, 2, 3, 4, 5, 6, 7 and 3 more")

    def test_the_home_folder_is_written_as_a_tilde(self):
        self.assertEqual(report.tilde("/Users/alice/Library/x", "/Users/alice"), "~/Library/x")
        self.assertEqual(report.tilde("/Users/alice", "/Users/alice/"), "~")
        self.assertEqual(report.tilde("/Users/alice2/x", "/Users/alice"), "/Users/alice2/x")

    def test_a_command_is_shown_without_its_wrappers(self):
        argv = ["/usr/bin/sudo", "-n", "--preserve-env=http_proxy", "--", "/usr/bin/arch", "-arm64",
                "/opt/local/bin/port", "-N", "uninstall", "jq", "@1.7.1_0"]
        self.assertEqual(report.typed(argv, path=""), "sudo /opt/local/bin/port -N uninstall jq @1.7.1_0")
        self.assertEqual(report.typed(["/usr/bin/arch", "-arm64", "/opt/homebrew/bin/brew", "install", "a b"],
                                      sudo=True, path=""), "sudo /opt/homebrew/bin/brew install 'a b'")
        self.assertEqual(report.typed(["/bin/kill", "-s", "INT", "--", "-12"], sudo=True, path=""),
                         "sudo /bin/kill -s INT -- -12")

    def test_a_bare_program_name_only_when_path_finds_that_file(self):
        first, second = self.path("first", "brew"), self.path("second", "brew")
        for program in (first, second):
            write_file(program, "#!/bin/sh\n", mode=0o755)
        path = os.pathsep.join([os.path.dirname(first), os.path.dirname(second)])
        self.assertEqual(report.typed([first, "install", "jq"], path=path), "brew install jq")
        self.assertEqual(report.typed([second, "install", "jq"], path=path), f"{second} install jq")
        self.assertEqual(report.typed([first, "install", "jq"], path="/nowhere"), f"{first} install jq")


if __name__ == "__main__":
    unittest.main()

"""Tests of redaction, the console and the text table"""

import io
import json
import unittest

from brew_ports import report


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


if __name__ == "__main__":
    unittest.main()

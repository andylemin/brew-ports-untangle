"""Tests of the state directory: run directories, backups, the journal, the lock and the dirty marker"""

import os
import re
import time
import unittest

from brew_ports import state
from tests.unit.helpers import TempDirTest


class RunDirTest(TempDirTest):
    """Tests of run ids, the `latest` link, run lookup and first-copy backups"""

    def test_run_id_format_and_latest_link(self):
        sd = self.state_dir()
        run = sd.new_run()
        self.assertRegex(run.run_id, r"^\d{8}-\d{6}-[0-9a-f]{6}$")
        self.assertEqual(os.path.realpath(os.path.join(sd.path, "latest")), os.path.realpath(run.path))
        latest = sd.latest_run()
        if latest is None:
            self.fail("the state directory has no latest run")
        self.assertEqual(latest.run_id, run.run_id)

    def test_two_runs_never_share_a_directory(self):
        sd = self.state_dir()
        ids = {sd.new_run().run_id for _ in range(5)}
        self.assertEqual(len(ids), 5)

    def test_run_rejects_path_tricks(self):
        sd = self.state_dir()
        for bad in ("", "..", "a/b", "."):
            with self.assertRaises(ValueError):
                sd.run(bad)

    def test_backup_first_copy_keeps_the_original(self):
        run = self.state_dir().new_run()
        rc = self.write("home/.zshrc", "original\n")
        first = run.backup_first_copy(rc)
        if first is None:
            self.fail(f"{rc} was not backed up")
        with open(rc, "w") as fh:
            fh.write("edited\n")
        second = run.backup_first_copy(rc)
        self.assertEqual(first, second)
        with open(first) as fh:
            self.assertEqual(fh.read(), "original\n")
        self.assertTrue(os.path.basename(first).startswith("%"))
        self.assertIsNone(run.backup_first_copy(self.path("missing")))


class EtcCopyTest(TempDirTest):
    """Tests of the readable first copy of an `/etc` file"""

    def test_first_copy_of_an_etc_file_is_kept(self):
        run = self.state_dir().new_run()
        shells = self.write("etc/shells", "/bin/zsh\n")
        first = run.etc_copy(shells, "shells")
        if first is None:
            self.fail(f"{shells} was not copied")
        self.assertEqual(first, run.sub("backup", "etc", "shells"))
        with open(shells, "w") as fh:
            fh.write("/bin/zsh\n/opt/local/bin/fish\n")
        self.assertEqual(run.etc_copy(shells, "shells"), first)
        with open(first) as fh:
            self.assertEqual(fh.read(), "/bin/zsh\n")
        self.assertEqual(run.etc_copy(self.write("etc/paths.d/homebrew", "/opt/homebrew/bin\n"),
                                      "paths.d/homebrew"), run.sub("backup", "etc", "paths.d", "homebrew"))
        self.assertIsNone(run.etc_copy(self.path("etc", "missing"), "missing"))


class JournalTest(TempDirTest):
    """Tests of journal results and of a line a crash cut short"""

    def test_result_lines_and_torn_tail(self):
        j = state.Journal(self.path("journal.jsonl"))
        j.append({"phase": 3, "action_id": "3.wget.install", "exit": 1})
        j.append({"phase": 3, "action_id": "3.wget.install", "result": "failed"})
        j.append({"phase": 3, "action_id": "3.wget.install", "result": "ok"})
        with open(j.path, "a") as fh:
            fh.write('{"phase": 3, "action_')   # a crash mid-line
        self.assertEqual(j.result(3, "3.wget.install"), "ok")
        self.assertIsNone(j.result(4, "3.wget.install"))
        self.assertEqual(len(j.entries()), 3)


class LockTest(TempDirTest):
    """Tests of the exclusive state lock"""

    def test_second_holder_is_refused(self):
        sd = self.state_dir()
        with sd.lock():
            other = state.StateDir(sd.path)
            with self.assertRaises(state.LockHeld):
                with other.lock():
                    pass
        with sd.lock():
            pass


class DirtyMarkerTest(TempDirTest):
    """Tests of the dirty marker: stale files and the resume check"""

    def test_marker_records_toucher_and_staleness(self):
        sd = self.state_dir()
        sd.ensure()
        plan = self.write("plan.json", "{}")
        old = time.time() - 60
        os.utime(plan, (old, old))
        self.assertFalse(sd.older_than_dirty(plan))
        sd.touch_dirty("RUN-A", "apply")
        self.assertTrue(sd.older_than_dirty(plan))
        marker = sd.dirty()
        if marker is None:
            self.fail("no dirty marker after touch_dirty")
        self.assertEqual((marker["run_id"], marker["command"]), ("RUN-A", "apply"))

    def test_resume_exempts_only_its_own_touch(self):
        sd = self.state_dir()
        started = time.time_ns() - 10 ** 9
        sd.touch_dirty("RUN-A", "apply")
        self.assertFalse(sd.marker_blocks_resume("RUN-A", started))
        sd.touch_dirty("RUN-B", "doctor --fix")
        self.assertTrue(sd.marker_blocks_resume("RUN-A", started))


class WriteUserFileTest(TempDirTest):
    """Tests of the user form of the `write` action"""

    def test_rewrite_keeps_inode_and_mode(self):
        path = self.write("rc", "a\nb\n")
        os.chmod(path, 0o600)
        before = os.stat(path)
        state.write_user_file(path, "c\n")
        after = os.stat(path)
        self.assertEqual(before.st_ino, after.st_ino)
        self.assertEqual(after.st_mode & 0o777, 0o600)
        with open(path) as fh:
            self.assertEqual(fh.read(), "c\n")

    def test_new_file_gets_0644(self):
        path = self.path("new_rc")
        old = os.umask(0)
        try:
            state.write_user_file(path, "x\n")
        finally:
            os.umask(old)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)

    def test_symlink_is_never_followed(self):
        target = self.write("real", "x")
        link = self.path("link")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            state.write_user_file(link, "y")


class SlugTest(unittest.TestCase):
    """Tests of path slugs and of the ISO 8601 time"""

    def test_slug(self):
        self.assertEqual(state.slug("/Users/u/.zshrc"), "%Users%u%.zshrc")
        self.assertTrue(re.match(r"^\d{4}-\d{2}-\d{2}T", state.now_iso()))


if __name__ == "__main__":
    unittest.main()

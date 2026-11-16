"""`rollback`: the replay of a run's backups, the backups only listed, and the login shell switched back"""

import dataclasses
import json
import os
import shutil
import unittest

from brew_ports import rollback as rb, runner as r, state
from brew_ports.model import Manager, Usability
from tests.unit.fixtures.macports.builders import make_registry, port
from tests.unit.fixtures.rollback import builders as b
from tests.unit.test_rollback import RollbackCase


def read(path):
    """Return a file's text

    @param path  the file
    @returns     its content
    """
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class BackupCase(RollbackCase):
    """A MacPorts source, a Homebrew target and the backups an apply run from one to the other leaves"""

    def setUp(self):
        super().setUp()
        self.ports = self.ports_instance()
        self.brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        make_registry(self.ports.portdbpath, ports=[port(1, "bash", "5.2.37")])
        self.host.selected[self.ports.binary] = {}
        self.ports_prefix, self.brew_prefix = self.ports.prefix, self.brew.prefix

    def run_of(self, *more):
        """Return an apply run from MacPorts to Homebrew whose snapshot covers every instance

        @param more  further instances the snapshot covers
        @returns     the run directory
        """
        instances = [self.brew, self.ports] + list(more)
        return b.source_run(self.sd, self.host, b.bundle(instances), instances,
                            the_plan=b.plan(self.brew, instances))

    def rc(self, run, name, before, after):
        """Write an rc file phase 7 rewrote or created, with its first backup and its write record

        @param run     the run that changed it
        @param name    the file's name in the home directory
        @param before  its text before the run; None for a file the run created
        @param after   its text after the run
        @returns       the file's path
        """
        path = self.write(os.path.join("Users", "alice", name), after)
        backup = self.write(run.backup_path(path), before) if before is not None else None
        b.journal(run, b.write_record(7, path, after, backup))
        return path

    def root(self, run, rel, before, after, phase=7):
        """Write an /etc file the run changed as root, with its report copy, root store copy and journal lines

        The journal holds the `cp -n -p` into the store, then the write record or the `rm` of a removal.

        @param run     the run that changed it
        @param rel     the file's path below `etc`
        @param before  its text before the run
        @param after   its text after the run; None for a file the run removed
        @param phase   the phase that changed it
        @returns       the file's path and its root store copy
        """
        path = self.path("etc", rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if after is not None:
            self.write(path, after)
        self.write(run.sub("backup", "etc", rel), before)
        store = self.write(self.path("store", run.run_id, state.slug(path)), before)
        entries = [b.command(phase, f"{phase}.root.store.{state.slug(path)}", [r.CP, "-n", "-p", path, store],
                             sudo=True)]
        if after is None:
            entries.append(b.command(phase, f"{phase}.remove.{state.slug(path)}", [r.RM, path], sudo=True))
        else:
            entries.append(b.write_record(phase, path, after, None, root=True))
        b.journal(run, *entries)
        return path, store


class UserFileTest(BackupCase):
    """The replay of a user's rc file: written back, listed with its diff, refused, removed or declined"""

    def lines(self):
        """Return an rc file's text before and after the run, which took MacPorts off its PATH

        @returns  the text before the run and the text after it
        """
        before = (f'export PATH="{self.ports_prefix}/bin:{self.ports_prefix}/sbin:$PATH"\n'
                  f'eval "$({self.brew_prefix}/bin/brew shellenv)"\n')
        return before, f'eval "$({self.brew_prefix}/bin/brew shellenv)"\n'

    def test_unchanged_file_is_replayed(self):
        run = self.run_of()
        before, after = self.lines()
        path = self.rc(run, ".zprofile", before, after)

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(read(path), before)
        self.assertEqual(read(self.rollback_dir().backup_path(path)), after)
        records = [e for e in self.rollback_dir().journal.entries() if e.get("kind") == "write"]
        self.assertEqual([(e["path"], e["sha256"]) for e in records],
                         [(path, r.sha256_bytes(before.encode("utf-8")))])
        self.assertIn(f"replay {path}: its edits concern {self.ports_prefix}", self.text)
        self.assertIn(f"replayed {path}", self.text)
        dirty = self.sd.dirty()
        if dirty is None:
            self.fail("the rollback left no dirty marker")
        self.assertEqual(dirty["command"], "rollback")

    def test_edited_file_is_listed_with_its_diff(self):
        run = self.run_of()
        before, after = self.lines()
        path = self.rc(run, ".zprofile", before, after)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("alias ll='ls -l'\n")

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(read(path), after + "alias ll='ls -l'\n")
        self.assertIn(f"listed, not replayed {path}: edited since the run: left alone", self.text)
        self.assertIn(f'    +export PATH="{self.ports_prefix}/bin:{self.ports_prefix}/sbin:$PATH"', self.text)
        self.assertIn("    -alias ll='ls -l'", self.text)
        self.assertIsNone(self.sd.dirty())

    def test_backup_naming_a_gone_manager_is_listed(self):
        gone = b.instance(self.tmp, Manager.BREW, "usr/local")
        run = self.run_of(gone)
        before = f'eval "$({gone.prefix}/bin/brew shellenv)"\nexport PATH="{self.ports_prefix}/bin:$PATH"\n'
        path = self.rc(run, ".zprofile", before, "")
        shutil.rmtree(gone.prefix)

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(read(path), "")
        self.assertIn(f"{gone.prefix} (Homebrew): skipped: no brew instance is found at {gone.prefix}",
                      self.text)
        self.assertIn(f"listed, not replayed {path}: it would bring back the lines of {gone.prefix}, which is still "
                      "gone", self.text)

    def test_a_skipped_source_leaves_the_file_alone(self):
        run = self.run_of()
        after = f'eval "$({self.brew_prefix}/bin/brew shellenv)"\n'
        path = self.rc(run, ".zprofile", f'export PATH="{self.ports_prefix}/bin:$PATH"\n', after)
        stuck = dataclasses.replace(self.ports, drivable=False, usability=Usability.PLATFORM_MISMATCH)

        code = self.rollback(run, [self.brew, stuck])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(read(path), after)
        self.assertIn(f"listed, not replayed {path}: its edits concern {self.ports_prefix}, which is not restored",
                      self.text)

    def test_a_file_the_run_created_stays_while_its_source_is_gone(self):
        run = self.run_of()
        path = self.rc(run, ".zprofile", None, f'eval "$({self.brew_prefix}/bin/brew shellenv)"\n')
        shutil.rmtree(self.ports_prefix)

        code = self.rollback(run, [self.brew])

        self.assertEqual(code, rb.EXIT_VERIFY)
        self.assertTrue(os.path.isfile(path))
        self.assertIn(f"listed, not replayed {path}: it would take out the lines of the target {self.brew_prefix}, "
                      f"and {self.ports_prefix} is not restored", self.text)

    def test_a_failed_reinstall_leaves_the_file_alone(self):
        run = self.run_of()
        before, after = self.lines()
        path = self.rc(run, ".zprofile", before, after)
        b.drop_rows(self.ports.portdbpath, "bash")
        self.host.fail = {"bash"}

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_VERIFY)
        self.assertEqual(read(path), after)
        self.assertIn(f"replay {path}: its edits concern {self.ports_prefix}", self.text)
        self.assertIn(f"listed, not replayed: {path}: its edits concern {self.ports_prefix}, which is not restored",
                      self.text)

    def test_a_file_the_run_created_is_removed(self):
        run = self.run_of()
        path = self.rc(run, ".bash_profile", None, f'eval "$({self.brew_prefix}/bin/brew shellenv)"\n')

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertFalse(os.path.exists(path))
        self.assertEqual(len(self.host.ran(r.RM, "-f", path)), 1)
        self.assertTrue(os.path.isfile(self.rollback_dir().backup_path(path)))

    def test_a_declined_replay_writes_nothing(self):
        run = self.run_of()
        before, after = self.lines()
        path = self.rc(run, ".zprofile", before, after)

        code = self.rollback(run, [self.brew, self.ports], yes=False)

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(read(path), after)
        self.assertIn("backups: not replayed", self.text)


class RootFileTest(BackupCase):
    """The replay of root files from the root backup store, and a root file whose readable copy is gone"""

    def test_root_files_come_back_from_the_store(self):
        run = self.run_of()
        paths, store = self.root(run, "paths", f"/usr/bin\n/bin\n{self.ports_prefix}/bin\n", "/usr/bin\n/bin\n")
        macports, _ = self.root(run, "paths.d/macports", f"{self.ports_prefix}/bin\n{self.ports_prefix}/sbin\n", None)

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(read(paths), f"/usr/bin\n/bin\n{self.ports_prefix}/bin\n")
        self.assertEqual(read(macports), f"{self.ports_prefix}/bin\n{self.ports_prefix}/sbin\n")
        self.assertEqual(len(self.host.ran(r.SUDO, "-n", "--", r.CP, "-p", store, paths)), 1)
        self.assertEqual(read(self.rollback_dir().sub("backup", "etc", "paths")), "/usr/bin\n/bin\n")
        self.assertIn(f"replayed {macports}", self.text)

    def test_root_file_without_copy_is_listed(self):
        run = self.run_of()
        paths, store = self.root(run, "paths", f"/usr/bin\n{self.ports_prefix}/bin\n", "/usr/bin\n")
        os.remove(run.sub("backup", "etc", "paths"))

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(read(paths), "/usr/bin\n")
        self.assertIn(f"listed, not replayed {paths}: its copy from before the run is only in the root backup store: "
                      f"sudo cp -p {store} {paths}", self.text)
        self.assertEqual(self.host.ran(r.CP, "-p"), [])

    def test_the_journal_names_every_file_the_run_changed(self):
        run = self.run_of()
        rc = self.rc(run, ".zprofile", f'export PATH="{self.ports_prefix}/bin:$PATH"\n', "")
        paths, store = self.root(run, "paths", "/usr/bin\n", "")
        removed, _ = self.root(run, "paths.d/macports", f"{self.ports_prefix}/bin\n", None)
        changes = rb.file_changes(rb.load_source(self.sd, run.run_id))
        self.assertEqual([(c.path, c.root, c.sha256 is None, c.known, c.store == store) for c in changes],
                         [(rc, False, False, True, False), (paths, True, False, True, True),
                          (removed, True, True, True, False)])


class LoginShellTest(BackupCase):
    """The login shell phase 5 switched: switched back, left alone when changed since, kept until the old one is back"""

    def switched_run(self, record_from=False):
        """Return a run whose phase 5 switched alice from MacPorts' bash to Homebrew's, which it added to /etc/shells

        The bash port is gone after the run.

        @param record_from  whether the journal records the old shell; else only the run's scan does
        @returns            the run, the old and the switched-to shell, and the `/etc/shells` stand-in
        """
        old, new = self.ports_prefix + "/bin/bash", self.brew_prefix + "/bin/bash"
        run = self.run_of()
        b.drop_rows(self.ports.portdbpath, "bash")
        entries = [b.command(5, rb.SHELL_ID, [rb.CHSH, "-s", new, b.USER], sudo=True)]
        if record_from:
            entries.append({"phase": 5, "action_id": rb.SHELL_ID, "result": "ok", "from": old})
        else:
            run.write_json("scan.json", json.dumps({"environment": {"login_shell": old}}))
        b.journal(run, *entries)
        shells, _ = self.root(run, "shells", f"/bin/bash\n/bin/zsh\n{old}\n",
                              f"/bin/bash\n/bin/zsh\n{old}\n{new}\n", phase=5)
        self.host.shell = new
        return run, old, new, shells

    def test_login_shell_goes_back(self):
        run, old, new, shells = self.switched_run()

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(self.host.ran(r.SUDO, "-n", "--", rb.CHSH, "-s", old, b.USER), [[r.SUDO, "-n", "--", rb.CHSH,
                                                                                         "-s", old, b.USER]])
        self.assertEqual(self.host.shell, old)
        self.assertIn(f"login shell: phase 5 switched alice from {old} to {new}", self.text)
        self.assertIn(f"login shell: switched back to {old}", self.text)
        self.assertEqual(read(shells), f"/bin/bash\n/bin/zsh\n{old}\n")

    def test_the_old_shell_comes_from_the_journal_record(self):
        run, old, _, _ = self.switched_run(record_from=True)

        self.assertEqual(self.rollback(run, [self.brew, self.ports]), rb.EXIT_OK)
        self.assertEqual(self.host.shell, old)

    def test_a_login_shell_changed_since_is_left_alone(self):
        run, old, new, shells = self.switched_run()
        self.host.shell = "/bin/zsh"

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(self.host.ran(rb.CHSH), [])
        self.assertEqual(self.host.shell, "/bin/zsh")
        self.assertIn(f"login shell: alice has /bin/zsh, not the {new} phase 5 set: left alone", self.text)
        self.assertEqual(read(shells), f"/bin/bash\n/bin/zsh\n{old}\n")

    def test_login_shell_stays_until_old_one_is_back(self):
        run, old, new, shells = self.switched_run()
        self.host.fail = {"bash"}

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_VERIFY)
        self.assertEqual(self.host.ran(rb.CHSH), [])
        self.assertEqual(self.host.shell, new)
        self.assertIn(f"login shell: {old} is not back, so alice keeps {new}", self.text)
        self.assertIn(f"listed, not replayed: {shells}: it would take out the lines of the target {self.brew_prefix}, "
                      f"and {self.ports_prefix} is not restored", self.text)
        self.assertEqual(read(shells), f"/bin/bash\n/bin/zsh\n{old}\n{new}\n")
        self.assertIn(f"{self.ports_prefix}: port bash: still absent after `port install`", self.text)

    def test_etc_shells_keeps_a_login_shell_that_stays(self):
        run, old, new, shells = self.switched_run()
        run.write_json("scan.json", json.dumps({"environment": {}}))

        code = self.rollback(run, [self.brew, self.ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(self.host.shell, new)
        self.assertIn("login shell: the shell before the run is not recorded", self.text)
        self.assertIn(f"listed, not replayed: {shells}: it does not list the login shell", self.text)
        self.assertEqual(read(shells), f"/bin/bash\n/bin/zsh\n{old}\n{new}\n")


if __name__ == "__main__":
    unittest.main()

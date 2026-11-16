"""The MacPorts registry: base's version order, the schemas from 1.203 to 1.215, backups and the integrity check"""

import os
import shutil
import sqlite3
import threading
import types
import unittest
from unittest import mock

from brew_ports.macports import registry
from tests.unit.fixtures.macports.builders import count_rows, make_registry, port
from tests.unit.helpers import TempDirTest

AS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


class VercmpTest(unittest.TestCase):
    """Version pairs and their order, each taken from base's C `vercmp`"""

    TABLE = [
        ("1.10", "1.9", 1), ("1.0", "1.0.1", -1), ("2.6.0", "2.6.0_1", -1), ("1.2-3", "1.2.3", 0),
        ("1.0a", "1.0", 1), ("1.0rc1", "1.0", 1), ("1.0", "1.0rc1", -1), ("9.6p1", "9.6pre", 1),
        ("2.0b", "2.0beta", 0), ("1.0a", "1.0.", 0), ("1½", "1¼", 0), ("1.0", "1.0.0", -1), ("abc", "123", -1),
    ]

    def test_table(self):
        for a, b, sign in self.TABLE:
            with self.subTest(a=a, b=b):
                result = registry.vercmp(a, b)
                self.assertEqual((result > 0) - (result < 0), sign)

    def test_antisymmetric(self):
        for left, right, sign in self.TABLE:
            if (left, right) == ("1.0a", "1.0."):
                continue
            with self.subTest(a=left, b=right):
                result = registry.vercmp(right, left)
                self.assertEqual((result > 0) - (result < 0), -sign)

    def test_asymmetric_case_of_the_c_algorithm(self):
        # The left side's trailing separator is skipped before the right side's letter is compared.
        self.assertEqual(registry.vercmp("1.0a", "1.0."), 0)
        self.assertEqual(registry.vercmp("1.0.", "1.0a"), -1)

    def test_leading_zeros_and_equal_strings(self):
        self.assertEqual(registry.vercmp("1.010", "1.10"), 0)
        self.assertEqual(registry.vercmp("3.12.7", "3.12.7"), 0)


class SplitVariantsTest(unittest.TestCase):
    """The split of a variants string into its tokens"""

    def test_split(self):
        self.assertEqual(registry.split_variants("+huge+python-x11"), ["+huge", "+python", "-x11"])
        self.assertEqual(registry.split_variants(""), [])
        self.assertEqual(registry.split_variants(None), [])


def sample_ports():
    """Return six `ports` rows: an unrequested zlib, two curls, a vim with variants and two foos

    @returns  the rows, as `port` builds them
    """
    return [
        port(1, "zlib", "1.3.1", requested=0, location="/x/zlib.tbz2"),
        port(2, "curl", "8.9.1", requested_variants="+http2", variants="+http2", negated_variants="-http2"),
        port(3, "curl", "8.10.0", state="imaged", variants="+http2"),
        port(4, "vim", "9.1.0", revision=1, variants="+huge", requested_variants="+huge-x11",
             negated_variants="-x11", cxx_stdlib="libstdc++", os_major="any", os_platform="any"),
        port(5, "foo", "1.10"), port(6, "foo", "1.9", state="imaged"),
    ]


class SchemaTest(TempDirTest):
    """Queries on a copy of each schema: rows, columns, snapshots, files and owners"""

    def open(self, schema, journal="wal"):
        """Create a registry of `sample_ports` in a schema and open a copy, closed when the test ends

        @param schema   the schema version
        @param journal  the journal mode
        @returns        the registry copy
        """
        portdb = self.path("var", "macports")
        make_registry(portdb, schema=schema, ports=sample_ports(), journal=journal,
                      files=[(2, "/opt/local/bin/curl", "/opt/local/bin/curl", 1, 1),
                             (3, "/opt/local/bin/curl", None, 0, 1),
                             (4, "/opt/local/bin/vim", "/opt/local/bin/vim.mp_1700000000", 1, 1),
                             (4, "/opt/local/share/vim/vimrc", "/opt/local/share/vim/vimrc", 1, 0),
                             (5, "/opt/local/binx/foo", "/opt/local/binx/foo", 1, 0)],
                      deps=[(2, "zlib"), (2, "zlib"), (4, "ncurses")],
                      snapshots=[(1, "first"), (2, "brew-ports 20261112-120000-abcdef"), (3, "first")]
                      if schema == "1.215" else ())
        reg = registry.Registry.open_copy(portdb)
        self.addCleanup(reg.close)
        return reg

    def test_current_schema(self):
        reg = self.open("1.215")
        self.assertEqual(reg.schema_version, "1.215")
        rows = {(r.name, r.version): r for r in reg.ports()}
        vim = rows[("vim", "9.1.0")]
        self.assertEqual(vim.spec_args, ["vim", "@9.1.0_1+huge"])
        self.assertEqual(vim.requested_variant_tokens, ["+huge", "-x11"])
        self.assertEqual((vim.cxx_stdlib, vim.cxx_stdlib_overridden, vim.os_major), ("libstdc++", 0, "any"))
        self.assertTrue(vim.active)
        self.assertFalse(rows[("curl", "8.10.0")].active)
        self.assertIs(rows[("zlib", "1.3.1")].requested, False)
        self.assertEqual(reg.snapshot_id("first"), 3)
        self.assertEqual(reg.snapshot_id("brew-ports 20261112-120000-abcdef"), 2)
        self.assertIsNone(reg.snapshot_id("none"))
        self.assertEqual([s.id for s in reg.snapshots()], [1, 2, 3])

    def test_order_by_version_uses_the_version_collation(self):
        reg = self.open("1.215")
        versions = [r.version for r in reg.ports() if r.name == "foo"]
        self.assertEqual(versions, ["1.9", "1.10"])

    def test_211_schema_has_no_snapshot_tables(self):
        reg = self.open("1.211")
        self.assertEqual(reg.schema_version, "1.211")
        self.assertFalse(reg.has_table("snapshots"))
        self.assertEqual(reg.snapshots(), [])
        self.assertIsNone(reg.snapshot_id("first"))
        vim = next(r for r in reg.ports() if r.name == "vim")
        self.assertEqual(vim.requested_variant_tokens, ["+huge", "-x11"])
        self.assertEqual(vim.cxx_stdlib, "libstdc++")

    def test_schema_203_reads_negated_variants(self):
        reg = self.open("1.203", journal="delete")
        self.assertEqual(reg.schema_version, "1.203")
        self.assertNotIn("requested_variants", reg.columns("ports"))
        rows = {(r.name, r.version): r for r in reg.ports()}
        self.assertEqual(rows[("vim", "9.1.0")].requested_variant_tokens, ["-x11"])
        self.assertEqual(rows[("curl", "8.9.1")].requested_variant_tokens, ["-http2"])
        self.assertIsNone(rows[("vim", "9.1.0")].cxx_stdlib)
        self.assertIsNone(rows[("vim", "9.1.0")].cxx_stdlib_overridden)

    def test_files_dependencies_and_owners(self):
        reg = self.open("1.215")
        files = reg.files(4)
        self.assertEqual([f.location for f in files],
                         ["/opt/local/bin/vim.mp_1700000000", "/opt/local/share/vim/vimrc"])
        self.assertEqual(reg.files(3)[0].location, "/opt/local/bin/curl")
        below = sorted((i, f.path) for i, f in reg.files_below("/opt/local/bin"))
        self.assertEqual(below, [(2, "/opt/local/bin/curl"), (3, "/opt/local/bin/curl"), (4, "/opt/local/bin/vim")])
        self.assertEqual(reg.dependencies(), {2: ["zlib"], 4: ["ncurses"]})
        self.assertEqual(reg.owner_of("/opt/local/bin/curl"), "curl")
        self.assertEqual(reg.owner_of("/opt/local/bin/vim.mp_1700000000"), "vim")
        self.assertIsNone(reg.owner_of("/opt/local/bin/nothing"))

    def test_open_backup_is_read_only(self):
        portdb = self.path("var", "macports")
        make_registry(portdb, schema="1.215", ports=sample_ports())
        dest = self.path("backup.db")
        registry.backup_registry(portdb, dest)
        with registry.Registry.open_backup(dest) as reg:
            self.assertEqual(len(reg.ports()), 6)
            with self.assertRaises(sqlite3.OperationalError):
                reg.conn.execute("DELETE FROM ports")


class ScriptedSource:
    """A source connection whose backup calls `progress` with scripted statuses"""

    def __init__(self, statuses):
        """Hold the statuses the backup reports

        @param statuses  the SQLite status of each step
        """
        self.statuses = statuses

    def backup(self, _dst, pages, progress):
        """Report each scripted status to `progress`, copying nothing

        @param _dst      the destination connection, which receives nothing
        @param pages     the pages per step, which the script ignores
        @param progress  the progress handler under test
        """
        del pages
        for status in self.statuses:
            progress(status, 0, 0)

    def close(self):
        """Close nothing: the source holds no file"""


class Clock:
    """A monotonic clock that advances by the same step at every reading"""

    def __init__(self, step):
        """Start at 0

        @param step  the seconds each reading adds
        """
        self.now, self.step = 0.0, step

    def monotonic(self):
        """Advance the clock by one step

        @returns  the time after the step
        """
        self.now += self.step
        return self.now


class BackupTest(TempDirTest):
    """Backups of live, locked, read-only and damaged registries, and the integrity check"""

    def portdb(self, *parts):
        """Return a path inside the test's `portdbpath`

        @param parts  the path's components below it
        @returns      the path
        """
        return self.path("var", "macports", *parts)

    def test_missing_file(self):
        os.makedirs(self.portdb("registry"))
        with self.assertRaises(registry.RegistryMissing):
            registry.backup_registry(self.portdb(), self.path("copy.db"))
        check = registry.check_registry(self.portdb())
        self.assertEqual(check.status, "missing")
        self.assertTrue((check.message or "").startswith("RegistryMissing: "))

    def test_backup_of_a_live_wal_registry(self):
        path = make_registry(self.portdb(), schema="1.215", ports=sample_ports())
        registry.backup_registry(self.portdb(), self.path("copy.db"))
        self.assertEqual(count_rows(self.path("copy.db")), 6)
        self.assertEqual(registry.check_registry(self.portdb()).status, "ok")
        self.assertFalse(os.path.exists(path + "-journal"))

    def test_locked_rollback_journal_registry_is_busy(self):
        path = make_registry(self.portdb(), schema="1.203", ports=sample_ports(), journal="delete")
        writer = sqlite3.connect(path, isolation_level=None)
        writer.execute("BEGIN EXCLUSIVE")
        self.addCleanup(writer.close)
        self.addCleanup(writer.execute, "ROLLBACK")
        with mock.patch.object(registry, "BUSY_TIMEOUT_S", 0.05):
            with self.assertRaises(registry.RegistryBusy):
                registry.backup_registry(self.portdb(), self.path("copy.db"), wait_s=0.3)
            check = registry.check_registry(self.portdb(), wait_s=0.3)
        self.assertEqual(check.status, "busy")
        self.assertTrue((check.message or "").startswith("RegistryBusy: "))

    @unittest.skipIf(AS_ROOT, "root ignores directory permissions")
    def test_wal_without_shm_in_read_only_dir_keeps_rows(self):
        source = make_registry(self.portdb("src"), schema="1.215", ports=sample_ports()[:5])
        writer = sqlite3.connect(source)
        writer.create_collation("VERSION", registry.vercmp)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO ports (id, name, version, revision, epoch, variants, state) "
                       "VALUES (6, 'foo', '1.9', 0, 0, '', 'imaged')")
        writer.commit()
        target = self.portdb("dst")
        directory = os.path.join(target, "registry")
        os.makedirs(directory)
        shutil.copy2(source, directory)
        shutil.copy2(source + "-wal", directory)
        writer.close()
        self.assertFalse(os.path.exists(os.path.join(directory, "registry.db-shm")))
        os.chmod(directory, 0o555)
        self.addCleanup(os.chmod, directory, 0o755)
        with mock.patch.object(registry, "_backup", wraps=registry._backup) as spy:
            registry.backup_registry(target, self.path("copy.db"))
        self.assertEqual(count_rows(self.path("copy.db")), 6)
        uris = [c.args[0] for c in spy.call_args_list]
        self.assertEqual(len(uris), 2)
        self.assertTrue(uris[0].endswith("?mode=ro"))
        self.assertFalse(uris[1].endswith("?mode=ro"))

    @unittest.skipIf(AS_ROOT, "root ignores file permissions")
    def test_a_large_wal_registry_with_a_wal_index_it_cannot_write(self):
        # The state `port` leaves: an empty WAL and a -shm that only root may write. Without a writable
        # wal-index, SQLite sees the file as changed at every read transaction.
        source = make_registry(self.portdb("src"), schema="1.215", ports=sample_ports())
        writer = sqlite3.connect(source, isolation_level=None)
        writer.create_collation("VERSION", registry.vercmp)
        writer.execute("BEGIN")
        for i in range(600):
            writer.execute("INSERT INTO ports (name, version, revision, epoch, variants, state, portfile) "
                           "VALUES (?, '1.0', 0, 0, '', 'installed', ?)", (f"big{i}", "x" * 3000))
        writer.execute("COMMIT")
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        target = self.portdb("dst")
        directory = os.path.join(target, "registry")
        os.makedirs(directory)
        for suffix in ("", "-wal", "-shm"):
            shutil.copy2(source + suffix, directory)
        writer.close()
        os.chmod(os.path.join(directory, "registry.db-shm"), 0o444)
        os.chmod(directory, 0o555)
        self.addCleanup(os.chmod, directory, 0o755)
        done = threading.Event()

        def backup():
            registry.backup_registry(target, self.path("copy.db"))
            done.set()
        threading.Thread(target=backup, daemon=True).start()
        self.assertTrue(done.wait(20), "the backup did not finish within 20 s")
        self.assertEqual(count_rows(self.path("copy.db")), 606)

    @unittest.skipIf(AS_ROOT, "root ignores directory permissions")
    def test_hot_journal_is_rolled_back_in_a_private_copy(self):
        source = make_registry(self.portdb("src"), schema="1.203", ports=sample_ports()[:5], journal="delete")
        writer = sqlite3.connect(source, isolation_level=None)
        writer.create_collation("VERSION", registry.vercmp)
        writer.execute("PRAGMA cache_size=10")
        writer.execute("BEGIN")
        for i in range(300):
            writer.execute("INSERT INTO ports (name, version, revision, epoch, variants, portfile) "
                           "VALUES (?, '1.0', 0, 0, '', ?)", (f"spill{i}", "x" * 3000))
        target = self.portdb("dst")
        directory = os.path.join(target, "registry")
        os.makedirs(directory)
        shutil.copy2(source, directory)
        shutil.copy2(source + "-journal", directory)
        writer.execute("ROLLBACK")
        writer.close()
        os.chmod(directory, 0o555)
        self.addCleanup(os.chmod, directory, 0o755)
        registry.backup_registry(target, self.path("copy.db"))
        self.assertEqual(count_rows(self.path("copy.db")), 5)
        os.chmod(directory, 0o755)
        self.assertEqual(registry.check_registry(target).status, "ok")

    def scripted(self, statuses, step, wait_s):
        """Run `_backup` against a scripted source and a clock that advances by `step` at every reading

        @param statuses  the SQLite status of each backup step
        @param step      the seconds each clock reading adds
        @param wait_s    the seconds without progress after which the backup is busy
        """
        fake_sqlite = types.SimpleNamespace(connect=lambda *a, **k: ScriptedSource(statuses),
                                            OperationalError=sqlite3.OperationalError)
        fake_time = types.SimpleNamespace(monotonic=Clock(step).monotonic, sleep=lambda s: None)
        with mock.patch.object(registry, "sqlite3", fake_sqlite), mock.patch.object(registry, "time", fake_time):
            registry._backup("file:x?mode=ro", self.path("copy.db"), wait_s)

    def test_slow_but_progressing_backup_is_not_busy(self):
        # 0.4 s per call: long past the 1 s deadline in total, never 1 s without a step that copied pages.
        self.scripted([0, 5, 0, 5, 0, 5, 0, 101], step=0.4, wait_s=1.0)

    def test_backup_without_progress_is_busy(self):
        with self.assertRaises(registry.RegistryBusy):
            self.scripted([0, 5, 5, 5, 5, 0], step=0.4, wait_s=1.0)

    def test_garbage_registry_is_damaged_after_three_attempts(self):
        os.makedirs(self.portdb("registry"))
        with open(self.portdb("registry", "registry.db"), "wb") as fh:
            fh.write(b"this is not an sqlite database" * 100)
        with mock.patch.object(registry, "backup_registry", wraps=registry.backup_registry) as spy:
            check = registry.check_registry(self.portdb())
        self.assertEqual(check.status, "damaged")
        self.assertEqual(spy.call_count, 3)
        self.assertIn("not a database", check.detail or "")

    def test_failed_integrity_check_is_retried_twice(self):
        make_registry(self.portdb(), schema="1.215", ports=sample_ports())
        bad = ["*** in database main ***", "row 3 missing from index port_name"]
        with mock.patch.object(registry, "_integrity", side_effect=[bad, bad, ["ok"]]):
            self.assertEqual(registry.check_registry(self.portdb()).status, "ok")
        with mock.patch.object(registry, "_integrity", return_value=bad) as integrity:
            check = registry.check_registry(self.portdb())
        self.assertEqual((check.status, integrity.call_count), ("damaged", 3))
        self.assertTrue((check.message or "").startswith("RegistryDamaged: *** in database main ***"))

    @unittest.skipIf(AS_ROOT, "root ignores directory permissions")
    def test_registry_the_user_cannot_read(self):
        make_registry(self.portdb(), schema="1.215", ports=sample_ports())
        os.chmod(self.portdb("registry"), 0)
        self.addCleanup(os.chmod, self.portdb("registry"), 0o755)
        with self.assertRaises(PermissionError):
            registry.backup_registry(self.portdb(), self.path("copy.db"))
        check = registry.check_registry(self.portdb())
        self.assertEqual(check.status, "unreadable")
        self.assertTrue((check.message or "").startswith("RegistryUnreadable: PermissionError"))


class ImageArchivesTest(TempDirTest):
    """The image archives under `software`, with dot files, stray files and empty directories left out"""

    def test_listing(self):
        portdb = self.path("var", "macports")
        self.assertEqual(registry.image_archives(portdb), {})
        self.write("var/macports/software/curl/curl-8.9.1_0+http2.darwin_25.arm64.tbz2")
        self.write("var/macports/software/curl/curl-8.10.0_0.darwin_25.arm64.tbz2")
        os.makedirs(self.path("var", "macports", "software", "empty"))
        self.write("var/macports/software/.turd_MacPorts")
        self.write("var/macports/software/stray-file")
        self.assertEqual(registry.image_archives(portdb), {
            "curl": ["curl-8.10.0_0.darwin_25.arm64.tbz2", "curl-8.9.1_0+http2.darwin_25.arm64.tbz2"]})


if __name__ == "__main__":
    unittest.main()

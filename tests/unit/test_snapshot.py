"""The phase 1 snapshot: every file of both managers, failed steps, reruns, and the readers"""

import json
import os
import sqlite3
import unittest

from brew_ports import model, runner as r, snapshot, state, system
from brew_ports.model import Manager
from tests.unit.fixtures.doctor import builders as b
from tests.unit.fixtures.macports.builders import make_registry, port
from tests.unit.helpers import TempDirTest, make_instance, make_package


class Host:
    """The FakeRunner's responder: what brew, port, launchctl and tmutil answer here"""

    def __init__(self, run_dir, *, brewfile_exit=0, info_exit=0, tmutil_exit=0, export=None, portdb=None):
        """Answer for one run, every step succeeding unless told otherwise

        @param run_dir        the run directory the `<run>` placeholder stands for
        @param brewfile_exit  the exit of `brew bundle dump`, which writes the Brewfile only on 0
        @param info_exit      the exit of `brew info --installed`
        @param tmutil_exit    the exit of `tmutil`
        @param export         the response to `port snapshot --export`; None for one that is not JSON
        @param portdb         the MacPorts `portdbpath` whose registry `port snapshot --create` writes
        """
        self.run_dir = run_dir
        self.brewfile_exit = brewfile_exit
        self.info_exit = info_exit
        self.tmutil_exit = tmutil_exit
        self.export = export
        self.portdb = portdb

    def real(self, text):
        """Return a path with the `<run>` placeholder put back to the run directory

        @param text  a path from the fake runner's key
        @returns     the real path
        """
        return text.replace("<run>", self.run_dir.path)

    def __call__(self, key):
        """Answer one command as this host does; a command it does not know is a KeyError

        @param key  the command's argv, with the placeholders put in
        @returns    the response
        """
        if key[:2] == ("/bin/launchctl", "print"):
            return b.NOT_FOUND
        if "bundle" in key and "dump" in key:
            path = self.real(next(a for a in key if a.startswith("--file="))[len("--file="):])
            if self.brewfile_exit == 0:
                with open(path, "w") as fh:
                    fh.write('tap "homebrew/core"\nbrew "wget"\ncask "firefox"\n')
            return r.FakeResponse(exit=self.brewfile_exit)
        if "info" in key and "--installed" in key:
            return r.FakeResponse(exit=self.info_exit, stdout="" if self.info_exit else '{"formulae": [], "casks": []}')
        if key[0] == snapshot.TMUTIL:
            return r.FakeResponse(exit=self.tmutil_exit, stderr="Failed to snapshot" if self.tmutil_exit else "")
        if "select" in key:
            return r.FakeResponse(stdout="Name     Selected   Options\n====     ========   =======\n"
                                         "python3  python312  none python312\n")
        if "--create" in key:
            conn = sqlite3.connect(os.path.join(self.portdb, "registry", "registry.db"))
            conn.execute("INSERT INTO snapshots (note) VALUES (?)", (snapshot.snapshot_note(self.run_dir),))
            conn.commit()
            conn.close()
            return r.FakeResponse()
        if "--export" in key:
            return self.export or r.FakeResponse(exit=1, stdout="not json")
        raise KeyError(key)


class SnapshotTest(TempDirTest):
    """The base of the snapshot tests: one run, and a Homebrew and a MacPorts instance in the temporary directory"""

    def setUp(self):
        super().setUp()
        self.sd = self.state_dir()
        self.run_dir = self.sd.new_run()
        self.brew = self.instance(Manager.BREW, "opt/homebrew")
        self.ports = self.instance(Manager.PORTS, "opt/local", portdbpath=self.path("opt", "local", "var", "macports"),
                                   features=("migrate", "snapshot", "snapshot_export"))

    def instance(self, manager, rel, **kw):
        """Return an instance whose prefix is a real directory in the temporary directory

        @param manager  the instance's manager
        @param rel      the prefix below the temporary directory, `/`-separated
        @param kw       `Instance` fields that override the defaults
        @returns        the instance
        """
        prefix = self.path(*rel.split("/"))
        os.makedirs(prefix, exist_ok=True)
        return make_instance(manager, prefix, identity=system.identity(prefix), spellings=(prefix,),
                             owned_roots=(prefix,), **kw)

    def fake(self, host):
        """Return a fake runner of the test's run, answered by a host

        @param host  the responder
        @returns     the runner
        """
        return r.FakeRunner(default=host, console=b.QuietConsole(), environ={"HOME": "/Users/alice"},
                            run_dir=self.run_dir)

    def receipt(self, path, **data):
        """Write a JSON receipt, making its directories

        @param path  the receipt file
        @param data  the receipt's fields
        @returns     the path
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            json.dump(data, fh)
        return path

    def cellar(self):
        """Lay out a Cellar of three formulae and a Caskroom of two casks and one symlinked token"""
        cellar = os.path.join(self.brew.prefix, "Cellar")
        os.makedirs(os.path.join(cellar, "wget", "1.24.5"))
        self.receipt(os.path.join(cellar, "wget", "1.25.0", "INSTALL_RECEIPT.json"), installed_on_request=True,
                     source={"tap": "homebrew/core"})
        self.receipt(os.path.join(cellar, "oldfmt", "2.0", "INSTALL_RECEIPT.json"), source={"tap": "alice/tools"})
        os.makedirs(os.path.join(cellar, "bare", "0.1"))
        room = os.path.join(self.brew.prefix, "Caskroom")
        os.makedirs(os.path.join(room, "firefox", "120.0"))
        os.makedirs(os.path.join(room, "firefox", ".metadata", "120.0", "20261101000000.000"))
        self.receipt(os.path.join(room, "firefox", ".metadata", "INSTALL_RECEIPT.json"), source={})
        os.makedirs(os.path.join(room, "mystery", "1.0"))
        os.makedirs(os.path.join(room, "mystery", ".metadata", "1.0", "20261101000000.000"))
        os.symlink("docker-desktop", os.path.join(room, "docker"))

    def registry(self):
        """Write the MacPorts registry: curl active and requested, zlib inactive and not requested"""
        make_registry(self.ports.portdbpath, ports=[
            port(1, "curl", "8.4.0", variants="+ssl", requested_variants="+ssl"),
            port(2, "zlib", "1.3", state="imaged", requested=0)])

    def bundle(self, services=()):
        """Return a scan of both instances with one cask, whose uninstall is privileged

        @param services  the scan's services
        @returns         the scan
        """
        packages = [make_package("firefox", kind="cask", prefix=self.brew.prefix, privileged_uninstall=True)]
        return b.bundle(instances=[self.brew, self.ports], packages=packages, services=list(services))


class HomebrewSnapshotTest(SnapshotTest):
    """Tests of the Homebrew snapshot: its files, failed steps, an undrivable instance and a rerun"""

    def test_every_homebrew_file(self):
        self.cellar()
        agents = self.path("Users", "alice", "Library", "LaunchAgents")
        plist = b.write_plist(os.path.join(agents, "sh.brew.wget.plist"), "sh.brew.wget", self.brew.prefix + "/bin/x")
        svc = b.service("sh.brew.wget", plist, self.brew.prefix, "wget", domain="gui/501", loaded=True, pid=7)
        rc = self.write("Users/alice/.zprofile", 'eval "$(/opt/homebrew/bin/brew shellenv)"\n')
        host = Host(self.run_dir)
        written = snapshot.write(self.fake(host), self.run_dir, self.bundle([svc]), [self.brew], rc_files=[rc])
        d = snapshot.brew_dir(self.run_dir, self.brew.prefix)
        self.assertEqual(os.path.basename(d), "brew-" + state.slug(self.brew.prefix))
        with open(os.path.join(d, snapshot.FORMULAE)) as fh:
            self.assertEqual(fh.read().splitlines()[1:], ["bare\tnone\t-\t0.1", "oldfmt\tnone\talice/tools\t2.0",
                                                          "wget\ttrue\thomebrew/core\t1.24.5 1.25.0"])
        casks, links = snapshot.read_casks(os.path.join(d, snapshot.CASKS))
        self.assertEqual([(c.token, c.privileged_install, c.privileged_uninstall, c.versions) for c in casks],
                         [("firefox", False, True, ["120.0"]), ("mystery", None, None, ["1.0"])])
        self.assertEqual([(l.token, l.target) for l in links], [("docker", "docker-desktop")])
        for rel in ("Cellar/wget/1.25.0", "Cellar/oldfmt/2.0", "Caskroom/firefox"):
            self.assertTrue(os.path.isfile(os.path.join(d, "receipts", rel, "INSTALL_RECEIPT.json")), rel)
        services = snapshot.read_services(os.path.join(d, snapshot.SERVICES))
        self.assertEqual([(s.label, s.loaded, s.domain) for s in services], [("sh.brew.wget", False, None)])
        with open(os.path.join(d, snapshot.BREWFILE)) as fh:
            self.assertIn('cask "firefox"', fh.read())
        self.assertFalse(os.path.exists(os.path.join(d, snapshot.BREWFILE + ".partial")))
        with open(os.path.join(d, snapshot.INSTALLED_JSON)) as fh:
            self.assertEqual(json.load(fh), {"formulae": [], "casks": []})
        self.assertTrue(os.path.isfile(os.path.join(snapshot.snapshot_dir(self.run_dir), "plists", state.slug(plist))))
        self.assertTrue(os.path.isfile(os.path.join(snapshot.snapshot_dir(self.run_dir), "rc", state.slug(rc))))
        self.assertTrue(snapshot.is_complete(self.run_dir))
        self.assertIn("complete", written)
        self.assertNotIn(snapshot.NOTES, written)
        self.assertEqual(snapshot.covered(self.run_dir), [(Manager.BREW, self.brew.prefix)])

    def test_failed_dump_and_info_leave_no_file_and_a_note(self):
        self.cellar()
        fake = self.fake(Host(self.run_dir, brewfile_exit=1, info_exit=1, tmutil_exit=1))
        written = snapshot.write(fake, self.run_dir, self.bundle(), [self.brew])
        d = snapshot.brew_dir(self.run_dir, self.brew.prefix)
        for name in (snapshot.BREWFILE, snapshot.BREWFILE + ".partial", snapshot.INSTALLED_JSON,
                     snapshot.INSTALLED_JSON + ".partial"):
            self.assertFalse(os.path.exists(os.path.join(d, name)), name)
        self.assertTrue(os.path.isfile(os.path.join(d, snapshot.FORMULAE)))
        with open(written[snapshot.NOTES]) as fh:
            notes = fh.read()
        self.assertIn("brew bundle dump exited 1", notes)
        self.assertIn("tmutil localsnapshot exited 1", notes)
        # What the commands say of it: the parts that are missing are counted apart from the disk snapshot.
        self.assertEqual(snapshot.outcome(written), [
            "2 parts of that record could not be saved: snapshot/notes.txt in the run folder lists them.",
            "macOS could not take a local snapshot of the disk. `brew-ports rollback` does not need one."])
        self.assertEqual(len(snapshot.outcome(written, disk=False)), 1)
        self.assertTrue(snapshot.is_complete(self.run_dir))
        # A later snapshot of the run adds to the same notes and counts only its own.
        earlier = snapshot.noted(self.run_dir)
        again = snapshot.write(self.fake(Host(self.run_dir, brewfile_exit=1)), self.run_dir, self.bundle(),
                               [self.brew], local_snapshot=False)
        self.assertEqual(snapshot.outcome(again, disk=False, earlier=earlier), [
            "1 part of that record could not be saved: snapshot/notes.txt in the run folder names it."])

    def test_a_whole_record_says_only_that_the_disk_has_a_snapshot(self):
        self.cellar()
        written = snapshot.write(self.fake(Host(self.run_dir)), self.run_dir, self.bundle(), [self.brew])
        self.assertEqual(snapshot.outcome(written), [
            "macOS also took a local snapshot of the disk, which it keeps for about a day or until it needs the "
            "space."])
        self.assertEqual(snapshot.outcome(written, disk=False), [])
        self.assertTrue(snapshot.is_complete(self.run_dir))

    def test_an_undrivable_instance_gets_disk_files_only(self):
        self.cellar()
        self.brew.drivable = False
        fake = self.fake(Host(self.run_dir))
        snapshot.write(fake, self.run_dir, self.bundle(), [self.brew], local_snapshot=False)
        self.assertFalse([c for c in fake.calls if "bundle" in c or "info" in c or c[0] == snapshot.TMUTIL])
        self.assertFalse(os.path.exists(os.path.join(snapshot.brew_dir(self.run_dir, self.brew.prefix),
                                                     snapshot.BREWFILE)))

    def test_a_rerun_overwrites_its_own_files(self):
        self.cellar()
        snapshot.write(self.fake(Host(self.run_dir)), self.run_dir, self.bundle(), [self.brew])
        first = sorted(os.listdir(snapshot.brew_dir(self.run_dir, self.brew.prefix)))
        snapshot.write(self.fake(Host(self.run_dir)), self.run_dir, self.bundle(), [self.brew])
        self.assertEqual(sorted(os.listdir(snapshot.brew_dir(self.run_dir, self.brew.prefix))), first)

    def test_filter_brewfile(self):
        text = 'tap "homebrew/core"\nbrew "wget"\ncask "firefox"\ncask "alice/tools/zed", args: { appdir: "~/A" }\n'
        self.assertEqual(snapshot.filter_brewfile(text, ["firefox", "zed"]), 'tap "homebrew/core"\nbrew "wget"\n')


class MacPortsSnapshotTest(SnapshotTest):
    """Tests of the MacPorts snapshot: its files, the port snapshot steps and the repair subset"""

    def export(self):
        """Return what `port snapshot --export` answers: the snapshot JSON, with exit 1

        @returns  the response
        """
        return r.FakeResponse(exit=1, stdout=b.fixture("ports-snapshot-export.json"))

    def test_every_macports_file_and_the_snapshot_steps(self):
        self.registry()
        daemon = self.path("Library", "LaunchDaemons", "org.macports.redis.plist")
        b.write_plist(daemon, "org.macports.redis", self.ports.prefix + "/bin/daemondo")
        svc = b.service("org.macports.redis", daemon, self.ports.prefix, "redis", kind="port", scope="system")
        fake = self.fake(Host(self.run_dir, export=self.export(), portdb=self.ports.portdbpath))
        snapshot.write(fake, self.run_dir, self.bundle([svc]), [self.ports])
        d = snapshot.ports_dir(self.run_dir, self.ports.prefix)
        self.assertTrue(os.path.isfile(os.path.join(d, snapshot.REGISTRY)))
        lines = snapshot.read_installed(os.path.join(d, snapshot.INSTALLED))
        self.assertEqual([(l.spec_args, l.requested, l.requested_variants, l.active, l.os_major) for l in lines],
                         [(["curl", "@8.4.0_0+ssl"], True, ["+ssl"], True, "25"),
                          (["zlib", "@1.3_0"], False, [], False, "25")])
        self.assertEqual([s.label for s in snapshot.read_services(os.path.join(d, snapshot.SERVICES))],
                         ["org.macports.redis"])
        self.assertEqual(snapshot.read_select(os.path.join(d, snapshot.SELECT)), [("python3", "python312")])
        self.assertEqual(snapshot.read_snapshot_id(os.path.join(d, snapshot.SNAPSHOT_ID)), 1)
        with open(os.path.join(d, snapshot.PORTS_SNAPSHOT)) as fh:
            self.assertEqual(json.load(fh)["metadata"]["type"], snapshot.SNAPSHOT_TYPE)
        create = [c for c in fake.calls if "--create" in c][0]
        self.assertEqual(create[:3], (r.SUDO, "-n", "--"))
        self.assertEqual(create[-2:], ("--note", "brew-ports <id>"))
        self.assertIn((r.SUDO, "-n", "--", "/usr/bin/arch", "-arm64", self.ports.prefix + "/bin/port", "-N", "snapshot",
                       "--export", "1"), fake.calls)
        self.assertEqual(snapshot.covered(self.run_dir), [(Manager.PORTS, self.ports.prefix)])

    def test_a_non_snapshot_export_is_not_kept(self):
        self.registry()
        fake = self.fake(Host(self.run_dir, portdb=self.ports.portdbpath))
        written = snapshot.write(fake, self.run_dir, self.bundle(), [self.ports], local_snapshot=False)
        d = snapshot.ports_dir(self.run_dir, self.ports.prefix)
        self.assertFalse(os.path.exists(os.path.join(d, snapshot.PORTS_SNAPSHOT)))
        self.assertTrue(os.path.isfile(os.path.join(d, snapshot.SNAPSHOT_ID)))
        with open(written[snapshot.NOTES]) as fh:
            self.assertIn("without the org.macports/snapshot/v1 JSON", fh.read())

    def test_an_undrivable_port_runs_no_command(self):
        self.registry()
        self.ports.features = ()
        self.ports.drivable = False
        fake = self.fake(Host(self.run_dir, portdb=self.ports.portdbpath))
        snapshot.write(fake, self.run_dir, self.bundle(), [self.ports], local_snapshot=False)
        self.assertEqual(fake.calls, [])
        d = snapshot.ports_dir(self.run_dir, self.ports.prefix)
        self.assertTrue(os.path.isfile(os.path.join(d, snapshot.INSTALLED)))
        self.assertFalse(os.path.exists(os.path.join(d, snapshot.SELECT)))

    def test_a_missing_registry_is_a_note(self):
        fake = self.fake(Host(self.run_dir, portdb=self.ports.portdbpath))
        self.ports.drivable = False
        written = snapshot.write(fake, self.run_dir, self.bundle(), [self.ports], local_snapshot=False)
        d = snapshot.ports_dir(self.run_dir, self.ports.prefix)
        self.assertFalse(os.path.exists(os.path.join(d, snapshot.REGISTRY)))
        self.assertFalse(os.path.exists(os.path.join(d, snapshot.INSTALLED)))
        with open(written[snapshot.NOTES]) as fh:
            self.assertIn("no registry.db", fh.read())

    def test_ports_records_are_the_repair_subset(self):
        self.registry()
        written = snapshot.write_ports_records(self.run_dir, self.ports, [])
        self.assertEqual(sorted(written), sorted(os.path.join("ports-" + state.slug(self.ports.prefix), n)
                                                 for n in (snapshot.REGISTRY, snapshot.INSTALLED, snapshot.SERVICES)))
        self.assertFalse(snapshot.is_complete(self.run_dir))


class ReaderTest(TempDirTest):
    """Tests of the snapshot readers on comments, short lines and several variants"""

    def test_readers_tolerate_comments_and_short_lines(self):
        path = self.write("f.txt", "# header\nwget\ttrue\t-\t1.0\nold\tnone\n")
        self.assertEqual([(f.name, f.requested, f.tap, f.versions) for f in snapshot.read_formulae(path)],
                         [("wget", True, None, ["1.0"]), ("old", None, None, [])])
        self.assertIsNone(snapshot.read_snapshot_id(self.path("absent")))
        self.assertEqual(snapshot.read_services(self.write("s.json", model.to_json([]))), [])

    def test_installed_txt_with_several_variants(self):
        path = self.write("a.txt", snapshot.INSTALLED_HEADER + "\nvim\t@9.1_0+huge-x11\ttrue\t+huge -x11\ttrue\t25\n"
                                   "zlib\t@1.3_0\tnone\t-\tfalse\t-\n")
        lines = snapshot.read_installed(path)
        self.assertEqual(len(lines), 2)
        vim, zlib = lines[0], lines[1]
        self.assertEqual((vim.spec_args, vim.requested, vim.requested_variants, vim.active, vim.os_major),
                         (["vim", "@9.1_0+huge-x11"], True, ["+huge", "-x11"], True, "25"))
        self.assertEqual((zlib.requested, zlib.requested_variants, zlib.active, zlib.os_major), (None, [], False, None))


if __name__ == "__main__":
    unittest.main()

"""MacPorts health fixes: the post-checks of the repairs, the leaves after a removal and the manager repairs"""

import dataclasses
import os
import unittest
from collections.abc import Sequence
from typing import Any
from unittest import mock

from brew_ports import model, scan, snapshot, system
from brew_ports.env import linkage as env_linkage
from brew_ports.macports import health, locate
from brew_ports.macports.portindex import PortEntry
from brew_ports.model import Severity
from brew_ports.report import tilde
from brew_ports.runner import ActionFailed, FakeResponse
from tests.unit.fixtures.macports.builders import fake_runner, port
from tests.unit.fixtures.macports_health.sites import (ARM64, PLATFORM, Site, macho, mode_executable, port_argv,
                                                       service, sql, sudo_port, write)
from tests.unit.helpers import TempDirTest

HOME = {"HOME": "/Users/alice"}


class VerifyTest(TempDirTest):
    """The post-checks of the missing-image, missing-file and broken-binaries repairs

    Every remedy below "succeeds" (FakeRunner exit 0) and changes nothing by itself; the
    test then changes the registry or the disk the way the real command would have.
    """

    def setUp(self):
        super().setUp()
        self.runner = fake_runner(self.tmp)            # replaced by the runner of each issues()
        self.bundle: scan.ScanBundle | None = None     # set by issues()

    def issues(self, site, linkage=None, responses=None):
        """Detect the findings of a site with a fake runner whose unknown commands succeed

        @param site       the MacPorts site
        @param linkage    the linkage scan; None for none
        @param responses  the fake runner's responses
        @returns          the findings
        """
        bundle = site.bundle(linkage=linkage)
        self.addCleanup(bundle.close)
        self.runner = fake_runner(self.tmp, responses or {}, default=FakeResponse(), run_dir=self.state_dir().new_run())
        self.bundle = bundle
        return health.detect(bundle, self.runner, platform=PLATFORM, default_prefix=site.prefix,
                             usr_local_cellar=self.path("none"))

    def apply(self, issue):
        """Run every remedy of a finding, asserting that none is manual

        @param issue  the finding
        """
        for action in issue.remedies:
            self.assertFalse(action.manual)
            self.runner.run(action)

    def verify(self, issue):
        """Run the post-check of a finding

        @param issue  the finding
        @returns      what `health.verify` decides
        """
        return health.verify(issue, self.runner, self.bundle)

    def test_missing_image_of_a_current_port(self):
        s = Site(self.tmp, registry_db=False)
        s.fill([port(1, "curl", "8.9.1", location=s.gone("curl", "8.9.1_0"))])
        issue = next(i for i in self.issues(s) if i.code == "ports-missing-image")
        self.apply(issue)
        self.assertIs(self.verify(issue), False)          # the image is still missing
        s.image("curl", "8.9.1_0")
        self.assertIs(self.verify(issue), True)
        sql(s.portdb, "UPDATE ports SET state = 'imaged'")
        self.assertIs(self.verify(issue), False)          # the port had an active row and has none

    def test_missing_image_of_an_outdated_port(self):
        s = Site(self.tmp, registry_db=False, entries=[PortEntry("curl", "8.10.1")])
        s.fill([port(1, "curl", "8.9.1", location=s.gone("curl", "8.9.1_0"))])
        issue = next(i for i in self.issues(s) if i.code == "ports-missing-image")
        self.assertIn("upgrade", issue.remedies[0].argv)
        self.apply(issue)
        self.assertIs(self.verify(issue), False)
        sql(s.portdb, "UPDATE ports SET state = 'imaged'")
        sql(s.portdb, "INSERT INTO ports (id, name, version, revision, epoch, variants, state, requested, location) "
                      "VALUES (2, 'curl', '8.10.1', 0, 0, '', 'installed', 1, ?)", s.image("curl", "8.10.1_0"))
        self.assertIs(self.verify(issue), True)           # the old row stays inactive: its own missing image

    def test_missing_image_of_an_inactive_row(self):
        s = Site(self.tmp, registry_db=False)
        s.fill([port(1, "curl", "8.9.1", location=s.image("curl", "8.9.1_0")),
                port(2, "curl", "8.8.0", state="imaged", location=s.gone("curl", "8.8.0_0"))])
        issue = next(i for i in self.issues(s) if i.code == "ports-missing-image")
        self.assertTrue(health.needs_terminal_answer(issue))
        self.apply(issue)
        self.assertIs(self.verify(issue), False)
        sql(s.portdb, "DELETE FROM ports WHERE id = 2")
        self.assertIs(self.verify(issue), True)

    def test_missing_file_needs_the_port_active_again(self):
        s = Site(self.tmp, registry_db=False)
        s.fill([port(1, "curl", "8.9.1", location=s.image("curl", "8.9.1_0"))],
               files=[(1, s.path("bin", "curl"), None, 1, 1)])
        issue = next(i for i in self.issues(s) if i.code == "ports-missing-file")
        self.apply(issue)
        self.assertIs(self.verify(issue), True)
        sql(s.portdb, "UPDATE ports SET state = 'imaged'")   # the activation did not happen
        self.assertIs(self.verify(issue), False)

    def test_broken_binaries_are_scanned_again(self):
        s = Site(self.tmp, registry_db=False)
        binary = macho(s.path("bin", "curl"), ARM64)
        lib = s.path("lib", "libz.1.dylib")
        gone = s.path("lib", "libgone.dylib")
        s.fill([port(1, "curl", "8.9.1", location=s.image("curl", "8.9.1_0"))], files=[(1, binary, None, 1, 1)])
        linkage = {"binaries": {binary: {"package": f"{s.prefix}|port|curl", "references": [
            {"name": gone, "class": "missing", "resolved": gone}]}}}
        otool = (env_linkage.OTOOL, "-l", binary)
        text = "%s:\nLoad command 0\n          cmd LC_LOAD_DYLIB\n      cmdsize 56\n         name %s (offset 24)\n"
        issue = next(i for i in self.issues(s, linkage, {otool: [FakeResponse(stdout=text % (binary, gone)),
                                                                 FakeResponse(stdout=text % (binary, lib))]})
                     if i.code == "ports-broken-binaries")
        self.apply(issue)
        self.assertIs(self.verify(issue), False)          # the rebuilt binary still names a missing library
        macho(lib, ARM64)
        self.assertIs(self.verify(issue), True)
        self.assertEqual(self.runner.calls.count(otool), 2)
        sql(s.portdb, "UPDATE ports SET state = 'imaged'")
        self.assertIs(self.verify(issue), False)

    def test_no_post_check_and_an_unreadable_registry(self):
        s = Site(self.tmp, registry_db=False)
        s.fill([port(1, "curl", "8.9.1", location=s.image("curl", "8.9.1_0")),
                port(2, "gettext", "0.22.5", requested=0, location=s.image("gettext", "0.22.5_0"))],
               files=[(1, s.path("bin", "curl"), None, 1, 1)])
        issues = self.issues(s)
        self.assertIsNone(self.verify(next(i for i in issues if i.code == "ports-unrequested-leaf")))
        missing_file = next(i for i in issues if i.code == "ports-missing-file")
        for name in os.listdir(os.path.join(s.portdb, "registry")):
            os.unlink(os.path.join(s.portdb, "registry", name))
        write(os.path.join(s.portdb, "registry", "registry.db"), "not a database " * 100)
        self.assertIs(self.verify(missing_file), False)


class LeavesTest(TempDirTest):
    """The unrequested leaves recomputed from a fresh registry backup after a removal"""

    def test_recomputed_from_a_fresh_backup(self):
        s = Site(self.tmp, registry_db=False)
        s.fill([port(1, "zlib", "1.3.1", requested=0, location=s.image("zlib", "1.3.1_0")),
                port(2, "gettext", "0.22.5", requested=0, location=s.image("gettext", "0.22.5_0"))],
               deps=[(2, "zlib")])
        bundle = s.bundle()
        self.addCleanup(bundle.close)
        runner = fake_runner(self.tmp, {})
        self.assertEqual([i.subject for i in health.recompute_leaves(s.prefix, runner, bundle)], ["gettext"])
        sql(s.portdb, "DELETE FROM ports WHERE name = 'gettext'")
        sql(s.portdb, "DELETE FROM dependencies WHERE id = 2")
        self.assertEqual([i.subject for i in health.recompute_leaves(s.prefix, runner, bundle)], ["zlib"])
        self.assertEqual(health.recompute_leaves(self.path("elsewhere"), runner, bundle), [])


class RepairTest(TempDirTest):
    """The manager repairs: the schema update, the base package procedure, `migrate --all` and their reports"""

    def setUp(self):
        super().setUp()
        self.run_dir = self.state_dir().new_run()
        self.r = fake_runner(self.tmp)                 # replaced by the runner of each runner()
        self.asked: list[str] = []                     # set by repair()
        self.shown: list[str] = []                     # set by repair()
        self.services: list[model.Service] = []        # set by migrate_site()
        for patcher in (mock.patch.object(health.brew_locate, "candidate_prefixes", return_value=[]),
                        mock.patch.object(locate, "_executable", mode_executable)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def runner(self, site, responses=None):
        """Return a fake runner, kept as `r`, that locates the site's usable 2.12.7 base on macOS 26

        @param site       the MacPorts site
        @param responses  further responses, which override the base ones
        @returns          the runner
        """
        tclsh = site.path("libexec", "macports", "bin", "tclsh8.6")
        base: dict[Sequence[str], Any] = {
            (locate.LIPO, "-archs", tclsh): FakeResponse(stdout="arm64\n"),
            tuple(port_argv(site.prefix, "version")): FakeResponse(stdout="Version: 2.12.7\n"),
            (system.SW_VERS, "-productVersion"): FakeResponse(stdout="26.0\n")}
        base.update(responses or {})
        self.r = fake_runner(self.tmp, base, run_dir=self.run_dir)
        return self.r

    def issue(self, code, site):
        """Return a HIGH finding of a code about the site's instance, without remedies

        @param code  the finding's code
        @param site  the MacPorts site
        @returns     the finding
        """
        return model.Issue(code=code, severity=Severity.HIGH, title="", subject=site.prefix,
                           instance_prefix=site.prefix, evidence=[], remedies=[], auto_fix=False, confirm_each=True,
                           repairs_install=False, blocks=())

    def repair(self, code, site, runner, *, confirm=None, default_prefix=None, environ=None):
        """Run one manager repair for the site's instance, recording its questions in `asked`

        @param code            the finding's code
        @param site            the MacPorts site the finding is about
        @param runner          the runner that runs the repair
        @param confirm         the answer to every question; None answers yes
        @param default_prefix  the default MacPorts prefix; None for the site's own
        @param environ         the environment; None for one with HOME alone
        @returns               the report lines, and whether the repair says the finding is gone
        """
        self.asked = []
        self.shown = []

        def ask(text):
            self.asked.append(text)
            return True if confirm is None else confirm

        lines, fixed = health.manager_repair(self.issue(code, site), runner, self.run_dir, environ or HOME,
                                             self.shown.append, confirm=ask,
                                             default_prefix=default_prefix or site.prefix, platform=PLATFORM)
        # Each line is shown once, as it comes, indented under the finding it belongs to.
        self.assertEqual(self.shown, ["  " + line for line in lines])
        return lines, fixed

    def sudo_calls(self):
        """Return the escalated commands the kept runner started

        @returns  the argv of each, in order
        """
        return [c for c in self.r.calls if c[:1] == ("/usr/bin/sudo",)]

    def test_schema_update_runs_version_as_root(self):
        s = Site(self.tmp, [port(1, "curl", "8.9.1")])
        runner = self.runner(s, {tuple(port_argv(s.prefix, "version")): [
            FakeResponse(exit=1, stderr="Error: attempt to write a readonly database\n"),
            FakeResponse(stdout="Version: 2.12.7\n")], sudo_port(s.prefix, "version"): FakeResponse()})
        lines, fixed = self.repair("ports-registry-schema-update", s, runner)
        self.assertEqual(self.sudo_calls(), [sudo_port(s.prefix, "version")])
        self.assertEqual((lines, fixed), ([f"sudo {s.path('bin', 'port')} -N version ... ok",
                                           f"The `port` command of MacPorts at {s.prefix} works."], True))
        self.assertEqual(self.asked, [])

    def test_a_repair_that_does_not_help_says_so(self):
        s = Site(self.tmp, [port(1, "curl", "8.9.1")])
        readonly = FakeResponse(exit=1, stderr="Error: attempt to write a readonly database\n")
        runner = self.runner(s, {tuple(port_argv(s.prefix, "version")): readonly,
                                 sudo_port(s.prefix, "version"): FakeResponse()})
        lines, fixed = self.repair("ports-registry-schema-update", s, runner)
        self.assertEqual((lines[-1], fixed),
                         (f"The `port` command of MacPorts at {s.prefix} still cannot run: Error: attempt to write a "
                          "readonly database", False))

    def test_a_cleared_issue_is_skipped(self):
        s = Site(self.tmp, [port(1, "curl", "8.9.1")])
        lines, fixed = self.repair("ports-registry-schema-update", s, self.runner(s))
        # None: the finding is gone, and no fix was made.
        self.assertEqual((lines, fixed), (["Nothing to do: this is in order already."], None))
        self.assertEqual(self.sudo_calls(), [])
        with self.assertRaises(ValueError):
            health.manager_repair(self.issue("ports-missing-image", s), self.r, self.run_dir, HOME, None,
                                  confirm=lambda t: True)

    def test_cannot_run_installs_base_at_default_prefix(self):
        s = Site(self.tmp, [port(1, "curl", "8.9.1")], binary=False)
        runner = self.runner(s)
        new = s.instance(binary=s.path("bin", "port"))

        def install(*_args, **_kw):
            write(s.path("bin", "port"), "#!/bin/sh\nexit 0\n", 0o755)
            return new
        with mock.patch.object(health.bootstrap, "bootstrap", side_effect=install) as boot:
            lines, fixed = self.repair("ports-cannot-run", s, runner)
        boot.assert_called_once_with(runner, self.run_dir, HOME, "arm64", macos_version="26.0",
                                     default_prefix=s.prefix)
        self.assertIn("MacPorts-<version>-26-<name>.pkg", self.asked[0])
        self.assertEqual((lines, fixed), ([
            "Downloading MacPorts' installer, checking its signature and running it. This can take a few minutes.",
            f"MacPorts 2.12.7 is installed at {s.prefix}, with its package list.",
            f"The `port` command of MacPorts at {s.prefix} works."], True))

    def test_cannot_run_declined_and_elsewhere(self):
        s = Site(self.tmp, [port(1, "curl", "8.9.1")], binary=False)
        with mock.patch.object(health.bootstrap, "bootstrap") as boot:
            lines, fixed = self.repair("ports-cannot-run", s, self.runner(s), confirm=False)
        boot.assert_not_called()
        self.assertEqual((lines, fixed), (["Nothing changed."], False))
        other = Site(self.tmp, [port(1, "curl", "8.9.1")])
        runner = self.runner(other, {tuple(port_argv(other.prefix, "version")): FakeResponse(exit=1, stderr="boom\n")})
        with mock.patch.object(health.bootstrap, "bootstrap") as boot:
            lines, fixed = self.repair("ports-cannot-run", other, runner, default_prefix=self.path("opt-local"),
                                       environ={"HOME": "/Users/alice", "PATH": other.path("bin")})
        boot.assert_not_called()
        self.assertEqual((lines, fixed), (["Fix: MacPorts' installer installs to /opt/local only, so build the "
                                           "current MacPorts from source with `./configure "
                                           f"--prefix={other.prefix}`."], False))
        self.assertEqual(self.sudo_calls(), [])

    def test_ports_are_not_built_again_by_a_port_that_cannot_run(self):
        """A repair that finds `port` broken says so; it never reads as done"""
        s = Site(self.tmp, [port(1, "curl", "8.9.1", os_major=24)])
        runner = self.runner(s, {tuple(port_argv(s.prefix, "version")): FakeResponse(exit=1, stderr="boom\n")})
        lines, fixed = self.repair("ports-built-for-other-os", s, runner)
        self.assertEqual((lines, fixed), ([f"The `port` command of MacPorts at {s.prefix} cannot run: boom",
                                           "Its ports were not built again."], False))
        self.assertEqual(self.sudo_calls(), [])

    def test_what_is_in_use_again_is_said_for_no_port_too(self):
        say = health._Report(None)
        health._not_back(say, [], 0, "installed.txt", str)
        health._not_back(say, [], 2, "installed.txt", str)
        self.assertEqual(say.lines, ["No port was in use.", "All 2 ports that were in use are in use again."])

    def migrate_site(self, **kw):
        """Make a site of curl, dbus and an unrequested zlib built for Darwin 24, keeping their services

        @param kw  further `Site` arguments, such as the base's version or `os_major`
        @returns   the site
        """
        s = Site(self.tmp, registry_db=False, **kw)
        s.fill([port(1, "curl", "8.9.1", requested_variants="+http2", location=s.image("curl", "8.9.1_0")),
                port(2, "dbus", "1.14.10", location=s.image("dbus", "1.14.10_0")),
                port(3, "zlib", "1.3.1", requested=0, os_major=24, location=s.image("zlib", "1.3.1_0"))])
        plist = "/Library/LaunchDaemons/org.macports.%s.plist"
        self.services = [service("org.macports.dbus", plist % "dbus", s.prefix, "dbus", loaded=True),
                         service("org.macports.curl", plist % "curl", s.prefix, "curl", loaded=True),
                         service("org.macports.zlib", plist % "zlib", s.prefix, "zlib")]
        return s

    def migrate_responses(self, s, exit_code=0):
        """Return the responses of a migration: `migrate --all`, then the load of dbus and the sync

        @param s          the MacPorts site
        @param exit_code  the exit status of `migrate --all`; a success leaves curl inactive, as base does
        @returns          the responses, keyed by argv
        """
        def migrate(_key):
            if exit_code == 0:
                sql(s.portdb, "UPDATE ports SET state = 'imaged' WHERE name = 'curl'")
            return FakeResponse(exit=exit_code)
        return {sudo_port(s.prefix, "migrate", "--all"): migrate, sudo_port(s.prefix, "load", "dbus"): FakeResponse(),
                sudo_port(s.prefix, "sync"): FakeResponse()}

    def test_platform_mismatch_migrates(self):
        s = self.migrate_site(os_major="24")
        runner = self.runner(s, self.migrate_responses(s))
        with mock.patch.object(health.env_services, "collect", return_value=self.services):
            lines, fixed = self.repair("ports-platform-mismatch", s, runner)
        self.assertEqual(self.sudo_calls(), [sudo_port(s.prefix, "migrate", "--all"),
                                             sudo_port(s.prefix, "load", "dbus"), sudo_port(s.prefix, "sync")])
        records = self.run_dir.sub("snapshot", "ports-" + s.prefix.replace("/", "%"))
        self.assertTrue(os.path.isfile(os.path.join(records, "registry", "registry.db")))
        installed = snapshot.read_installed(os.path.join(records, "installed.txt"))
        self.assertEqual([(p.spec_args, p.requested, p.requested_variants, p.active, p.os_major) for p in installed],
                         [(["curl", "@8.9.1_0"], True, ["+http2"], True, "25"),
                          (["dbus", "@1.14.10_0"], True, [], True, "25"),
                          (["zlib", "@1.3.1_0"], False, [], True, "24")])
        self.assertEqual([svc.label for svc in snapshot.read_services(os.path.join(records, "services.json"))],
                         ["org.macports.dbus", "org.macports.curl", "org.macports.zlib"])
        port_bin = s.path("bin", "port")
        self.assertEqual(lines[:-1], [
            f"Saved MacPorts' record of installed ports in {tilde(records)}.",
            f"sudo {port_bin} -N migrate --all ... ok",
            # curl is still stored, switched off: "not in use" says no more than the record does.
            "1 port that was in use is not in use again: curl",
            f"  To bring curl back: sudo {port_bin} -N install --no-rev-upgrade curl +http2",
            "The service of dbus runs again.",
            f"sudo {port_bin} -N sync ... ok"])
        # The fake `port migrate` leaves MacPorts itself as it was, and the last line and the result say so.
        self.assertEqual((lines[-1], fixed), (
            f"The `port` command of MacPorts at {s.prefix} still cannot run: MacPorts was built for macOS 15 "
            "(Darwin 24); this Mac runs macOS 26 (Darwin 25)", False))
        self.assertEqual(self.asked, [])

    def test_a_failed_migrate_is_reported_and_raised(self):
        s = self.migrate_site(os_major="24")
        responses = self.migrate_responses(s, exit_code=1)
        responses[sudo_port(s.prefix, "load", "curl")] = FakeResponse()
        runner = self.runner(s, responses)
        with mock.patch.object(health.env_services, "collect", return_value=self.services):
            with self.assertRaises(ActionFailed):
                self.repair("ports-platform-mismatch", s, runner)
        self.assertEqual(self.sudo_calls()[1:], [sudo_port(s.prefix, "load", "curl"),
                                                 sudo_port(s.prefix, "load", "dbus"), sudo_port(s.prefix, "sync")])
        # The report came before the error: the command that failed, then what is in use and what runs again.
        self.assertEqual(self.shown[1:3], [f"  sudo {s.path('bin', 'port')} -N migrate --all ... failed (exit 1)",
                                           "  All 3 ports that were in use are in use again."])

    def test_no_migrate_without_the_registry_backup(self):
        s = self.migrate_site(os_major="24")
        for name in os.listdir(os.path.join(s.portdb, "registry")):
            os.unlink(os.path.join(s.portdb, "registry", name))
        write(os.path.join(s.portdb, "registry", "registry.db"), "not a database " * 100)
        runner = self.runner(s, self.migrate_responses(s))
        with mock.patch.object(health.env_services, "collect", return_value=self.services):
            lines, fixed = self.repair("ports-platform-mismatch", s, runner)
        self.assertTrue(lines[0].startswith("MacPorts' record of installed ports could not be saved first ("))
        self.assertTrue(lines[0].endswith("), so `port migrate` was not run."))
        self.assertFalse(fixed)
        self.assertEqual(self.sudo_calls(), [])

    def test_old_base_installs_the_package_then_migrates(self):
        s = self.migrate_site(os_major="24", version="2.8.1")
        runner = self.runner(s, self.migrate_responses(s))
        new = dataclasses.replace(s.instance(), version="2.12.7", features=locate.features_for("2.12.7"))
        with mock.patch.object(health.env_services, "collect", return_value=self.services), \
                mock.patch.object(health.bootstrap, "bootstrap", return_value=new) as boot:
            lines, _ = self.repair("ports-platform-mismatch", s, runner)
        boot.assert_called_once()
        self.assertEqual(len(self.asked), 1)
        self.assertEqual(self.sudo_calls(), [sudo_port(s.prefix, "migrate", "--all"),
                                             sudo_port(s.prefix, "load", "dbus")])
        self.assertEqual(lines[:2], [
            "Downloading MacPorts' installer, checking its signature and running it. This can take a few minutes.",
            f"MacPorts 2.12.7 is installed at {s.prefix}, with its package list."])

    def test_old_base_elsewhere_is_manual(self):
        s = self.migrate_site(os_major="24", version="2.8.1")
        runner = self.runner(s)
        lines, fixed = self.repair("ports-platform-mismatch", s, runner, default_prefix=self.path("opt-local"),
                                   environ={"HOME": "/Users/alice", "PATH": s.path("bin")})
        # The installed 2.8.1 has no `port migrate`: the line names the current MacPorts, and its own `port`.
        self.assertEqual(lines, ["Fix: MacPorts' installer installs to /opt/local only, so build the current "
                                 f"MacPorts from source with `./configure --prefix={s.prefix}`, then run `sudo "
                                 f"{s.path('bin', 'port')} -N migrate --all`."])
        self.assertFalse(fixed)
        self.assertEqual(self.sudo_calls(), [])

    def test_other_os_is_skipped_once_the_active_ports_are_rebuilt(self):
        s = Site(self.tmp, registry_db=False)
        s.fill([port(1, "curl", "8.9.1", location=s.image("curl", "8.9.1_0")),
                port(2, "zlib", "1.3.1", state="imaged", os_major=24, location=s.image("zlib", "1.3.1_0"))])
        with mock.patch.object(health.env_services, "collect", return_value=[]):
            lines, fixed = self.repair("ports-built-for-other-os", s, self.runner(s, self.migrate_responses(s)))
        self.assertEqual((lines, fixed), (["Nothing to do: this is in order already."], None))
        self.assertEqual(self.sudo_calls(), [])

    def test_other_os_migrates_then_syncs(self):
        s = self.migrate_site()
        runner = self.runner(s, self.migrate_responses(s))
        with mock.patch.object(health.env_services, "collect", return_value=self.services):
            lines, fixed = self.repair("ports-built-for-other-os", s, runner)
        self.assertEqual(self.sudo_calls()[-1], sudo_port(s.prefix, "sync"))
        # zlib, built for the older macOS, is still in use after the fake `port migrate`: the repair says so.
        self.assertEqual((lines[-1], fixed),
                         ("Some ports in use are still built for another version of macOS.", False))
        old = self.migrate_site(version="2.9.3")
        lines, fixed = self.repair("ports-built-for-other-os", old, self.runner(old))
        port_bin = old.path("bin", "port")
        self.assertEqual((lines, fixed), ([f"Fix: MacPorts 2.9.3 is too old for `port migrate`. Run `sudo {port_bin} "
                                           f"selfupdate`, then `sudo {port_bin} -N migrate --all`."], False))
        self.assertEqual(self.sudo_calls(), [])


if __name__ == "__main__":
    unittest.main()

"""The MacPorts health detectors: each `ports-` finding, its remedies, and what `doctor --fix` reads of them"""

import os
import time
import unittest

from brew_ports import model, state, system
from brew_ports.env import services as env_services
from brew_ports.macports import health
from brew_ports.macports.portindex import PortEntry
from brew_ports.model import Blocks, OnFailure, Severity, Usability
from brew_ports.runner import RM, FakeResponse
from tests.unit.fixtures.macports.builders import fake_runner, port, write_sources_conf
from tests.unit.fixtures.macports_health.sites import (ARM64, PLATFORM, X86_64, Site, macho, port_argv, service, sql,
                                                       write)
from tests.unit.helpers import TempDirTest


class HealthTest(TempDirTest):
    """Helpers of the MacPorts health tests: a site per test, and the detectors run with a fake runner"""

    def setUp(self):
        super().setUp()
        self.run_dir: state.RunDir | None = None      # set by each detect()
        self.runner = fake_runner(self.tmp)            # replaced by the runner of each detect()

    def site(self, *args, **kw):
        """Make a site in the test's temporary directory

        @param args  the `Site` arguments after the directory
        @param kw    the `Site` keyword arguments
        @returns     the site
        """
        return Site(self.tmp, *args, **kw)

    def detect(self, bundle, responses=None, *, default_prefix=None, run_dir=True, now=None, cellar=None):
        """Run the MacPorts detectors over a bundle, with a fake runner

        @param bundle          the scan bundle, closed when the test ends
        @param responses       the fake runner's canned responses
        @param default_prefix  the default MacPorts prefix; None for the bundle's first instance
        @param run_dir         give the runner a run directory
        @param now             the clock's time; None for the current time
        @param cellar          the `/usr/local/Cellar` the detectors look at; None for a path that does not exist
        @returns               the findings
        """
        self.addCleanup(bundle.close)
        self.run_dir = self.state_dir().new_run() if run_dir else None
        self.runner = fake_runner(self.tmp, responses or {}, run_dir=self.run_dir)
        return health.detect(bundle, self.runner, platform=PLATFORM,
                             default_prefix=default_prefix or bundle.ports[0][0].prefix, now=now,
                             usr_local_cellar=cellar or os.path.join(self.tmp, "no-cellar"))

    def only(self, issues, code):
        """Return the findings of one code

        @param issues  the findings
        @param code    the code
        @returns       the findings of that code, in order
        """
        return [i for i in issues if i.code == code]

    def one(self, issues, code):
        """Return the one finding of a code, asserting that there is exactly one

        @param issues  the findings
        @param code    the code
        @returns       the finding
        """
        found = self.only(issues, code)
        self.assertEqual(len(found), 1, [(i.code, i.subject, i.evidence) for i in issues])
        return found[0]

    def argvs(self, issue):
        """Return the argv of each remedy of a finding

        @param issue  the finding
        @returns      the argvs, in remedy order
        """
        return [a.argv for a in issue.remedies]

    def step(self, issue):
        """Return the `<step>` of an issue's first remedy id

        @param issue  the finding
        @returns      the step; None for a finding without a remedy
        """
        if not issue.remedies:
            return None
        return issue.remedies[0].action_id[len(self.id_head(issue)):]

    def id_head(self, issue):
        """Return the head of an issue's remedy ids, up to the step

        It is `doctor.<code>.<instance>.<subject>.`, or `doctor.<code>.<subject>.` when the subject is a
        path that already names the instance.

        @param issue  the finding
        @returns      the head, ending in a dot
        """
        subject = issue.subject.replace("/", "%")
        tag = (issue.instance_prefix or "").replace("/", "%")
        return f"doctor.{issue.code}.{subject if not tag or tag in subject else tag + '.' + subject}."


class DiagnoseTest(HealthTest):
    """`port diagnose` warnings: one finding each, the missing files folded per port, undrivable instances skipped"""

    STDERR = ("Warning: Xcode Command Line Tools are not installed! To install them, please enter the command:\n"
              "                                    xcode-select --install\n"
              "Warning: found a DYLD_* environment variable. These are known to cause issues with MacPorts.\n"
              "Warning: couldn't find file '/opt/local/bin/a' for port 'foo'. Please deactivate and reactivate the "
              "port to fix this issue.\n"
              "Warning: couldn't find file '/opt/local/bin/b' for port 'foo'. Please deactivate and reactivate the "
              "port to fix this issue.\n"
              "Warning: found a DYLD_* environment variable. These are known to cause issues with MacPorts.\n")

    def test_warnings_fold_missing_files_per_port(self):
        site = self.site()
        key = tuple(port_argv(site.prefix, "diagnose", "--quiet"))
        found = self.detect(site.bundle(), {key: FakeResponse(stderr=self.STDERR)})
        issues = self.only(found, "ports-diagnose-warning")
        self.assertEqual([i.subject for i in issues], [site.prefix, site.prefix, "foo"])
        self.assertEqual(issues[0].remedies[0].description,
                         "Warning: Xcode Command Line Tools are not installed! To install them, please enter the "
                         "command: xcode-select --install")
        self.assertTrue(all(i.severity is Severity.MEDIUM and i.remedies[0].manual for i in issues))
        self.assertEqual(issues[2].evidence, ["port diagnose: missing /opt/local/bin/a",
                                              "port diagnose: missing /opt/local/bin/b"])
        self.assertIn("(and 1 more files of foo)", issues[2].remedies[0].description)
        self.assertTrue(self.step(issues[0]).startswith("warning-"))
        self.assertFalse(any(i.confirm_each or i.auto_fix or i.blocks for i in issues))

    def test_no_warning_and_undrivable_instances(self):
        site = self.site()
        key = tuple(port_argv(site.prefix, "diagnose", "--quiet"))
        self.assertEqual(self.only(self.detect(site.bundle(), {key: FakeResponse()}), "ports-diagnose-warning"), [])
        bundle = site.bundle(site.instance(usability=Usability.PLATFORM_MISMATCH))
        found = self.detect(bundle, {key: FakeResponse(stderr=self.STDERR)})
        self.assertEqual(self.only(found, "ports-diagnose-warning"), [])
        self.assertNotIn(key, self.runner.calls)
        self.assertTrue(any("port diagnose skipped" in n for n in bundle.notes))

    def test_parse_diagnose(self):
        text = "Checking for things\nWarning: one\n  two\nError: three\nPlease refer to the guide\n  ignored\n"
        self.assertEqual(health.parse_diagnose(text), ["Warning: one two", "Error: three"])


class BaseTest(HealthTest):
    """The findings about base itself: platform mismatch, damaged, busy and missing registries, cannot-run"""

    def test_platform_mismatch_with_migrate(self):
        site = self.site(os_major="24")
        inst = site.instance(usability=Usability.PLATFORM_MISMATCH, usability_detail="base is built for darwin 24")
        issue = self.one(self.detect(site.bundle(inst)), "ports-platform-mismatch")
        self.assertEqual(self.argvs(issue),
                         [port_argv(site.prefix, "migrate", "--all"), port_argv(site.prefix, "sync")])
        self.assertTrue(all(a.sudo for a in issue.remedies))
        self.assertEqual((issue.severity, issue.confirm_each, issue.blocks), (Severity.HIGH, True, (Blocks.TARGET,)))
        self.assertEqual(issue.evidence[0], "base is built for darwin 24")
        slugged = site.prefix.replace("/", "%")
        self.assertEqual([a.action_id for a in issue.remedies],
                         [f"doctor.ports-platform-mismatch.{slugged}.migrate",
                          f"doctor.ports-platform-mismatch.{slugged}.sync"])
        self.assertIsNone(health.removes_package(issue))

    def test_platform_mismatch_on_an_old_base(self):
        site = self.site(version="2.8.1", os_major="24")
        inst = site.instance(usability=Usability.PLATFORM_MISMATCH)
        issue = self.one(self.detect(site.bundle(inst)), "ports-platform-mismatch")
        self.assertEqual([a.kind for a in issue.remedies], ["note", "command", "command"])
        self.assertEqual(self.argvs(issue)[1:], [port_argv(site.prefix, "sync"),
                                                 port_argv(site.prefix, "migrate", "--all")])
        self.assertTrue(issue.confirm_each)
        elsewhere = self.one(self.detect(site.bundle(inst), default_prefix=self.path("other")),
                             "ports-platform-mismatch")
        self.assertEqual([a.kind for a in elsewhere.remedies], ["note"])
        self.assertIn(f"./configure --prefix={site.prefix}", elsewhere.remedies[0].description)
        self.assertFalse(elsewhere.confirm_each)
        self.assertEqual(elsewhere.blocks, (Blocks.TARGET,))

    def test_platform_mismatch_from_autoconf_alone(self):
        site = self.site(os_major="24", binary=False)
        issue = self.one(self.detect(site.bundle(site.instance(usability=Usability.MISSING_BINARY))),
                         "ports-platform-mismatch")
        self.assertIn("Darwin 24", issue.evidence[0])
        self.assertEqual(issue.remedies[0].kind, "note")
        self.assertEqual(self.only(self.detect(self.site().bundle()), "ports-platform-mismatch"), [])

    def test_damaged_registry_lists_image_archives(self):
        site = self.site()
        site.image("curl", "8.9.1_0")
        inst = site.instance(inventory_known=False, inventory_error="RegistryDamaged: malformed",
                             usability=Usability.DAMAGED_REGISTRY)
        issue = self.one(self.detect(site.bundle(inst)), "ports-damaged-registry")
        self.assertEqual(issue.evidence[0], "RegistryDamaged: malformed")
        self.assertIn("image archive: curl: curl-8.9.1_0.darwin_25.arm64.tbz2", issue.evidence)
        self.assertEqual((issue.remedies, issue.blocks), ([], (Blocks.TARGET, Blocks.REMOVE)))
        self.assertEqual(self.only(self.detect(self.site().bundle()), "ports-damaged-registry"), [])

    def test_busy_registry_is_not_damaged(self):
        site = self.site()
        inst = site.instance(inventory_known=False, inventory_error="RegistryBusy: no progress for 30 s")
        issues = self.detect(site.bundle(inst))
        issue = self.one(issues, "ports-registry-busy")
        self.assertEqual((issue.severity, issue.blocks), (Severity.CRITICAL, (Blocks.ANY,)))
        self.assertTrue(issue.remedies[0].manual)
        self.assertEqual(self.only(issues, "ports-damaged-registry"), [])
        self.assertEqual(self.only(self.detect(self.site().bundle()), "ports-registry-busy"), [])

    def test_schema_update_runs_port_version_as_root(self):
        site = self.site()
        issue = self.one(self.detect(site.bundle(site.instance(usability=Usability.READONLY_REGISTRY))),
                         "ports-registry-schema-update")
        self.assertEqual(self.argvs(issue), [port_argv(site.prefix, "version")])
        self.assertTrue(issue.remedies[0].sudo and issue.confirm_each)
        self.assertEqual(issue.blocks, (Blocks.TARGET,))
        self.assertEqual(self.only(self.detect(self.site().bundle()), "ports-registry-schema-update"), [])

    def test_cannot_run_needs_registry_rows(self):
        site = self.site([port(1, "curl", "8.9.1")], binary=False)
        inst = site.instance(usability=Usability.MISSING_BINARY)
        issue = self.one(self.detect(site.bundle(inst)), "ports-cannot-run")
        self.assertEqual([a.kind for a in issue.remedies], ["note", "command"])
        self.assertEqual(issue.remedies[1].argv, port_argv(site.prefix, "sync"))
        self.assertEqual((issue.confirm_each, issue.blocks), (True, (Blocks.TARGET,)))
        elsewhere = self.one(self.detect(site.bundle(inst), default_prefix=self.path("other")), "ports-cannot-run")
        self.assertEqual(([a.kind for a in elsewhere.remedies], elsewhere.confirm_each), (["note"], False))
        empty = self.site([], binary=False)
        found = self.detect(empty.bundle(empty.instance(usability=Usability.CANNOT_RUN)))
        self.assertEqual(self.only(found, "ports-cannot-run"), [])

    def test_no_registry_needs_a_known_empty_inventory(self):
        site = self.site(registry_db=False)
        known = site.instance(usability=Usability.NO_REGISTRY, inventory_known=True)
        issue = self.one(self.detect(site.bundle(known)), "ports-no-registry")
        self.assertEqual(self.argvs(issue), [port_argv(site.prefix, "version")])
        self.assertTrue(issue.remedies[0].sudo)
        self.assertEqual(issue.blocks, (Blocks.TARGET,))
        lost = site.instance(usability=Usability.NO_REGISTRY, inventory_known=False,
                             inventory_error="RegistryMissing: registry.db; images or files of ports remain")
        issues = self.detect(site.bundle(lost))
        self.assertEqual(self.only(issues, "ports-no-registry"), [])
        self.assertEqual(len(self.only(issues, "ports-damaged-registry")), 1)


class RowsTest(HealthTest):
    """The findings about registry rows: missing images, inactive versions, leaves, obsolete and replaced ports"""

    def build(self):
        """Make a site of nine rows, some without their image, and a PortIndex with one replaced port

        @returns  the site
        """
        s = self.site(registry_db=False)
        s.fill([
            port(1, "curl", "8.9.1", location=s.gone("curl", "8.9.1_0")),
            port(2, "curl", "8.8.0", state="imaged", location=s.gone("curl", "8.8.0_0")),
            port(3, "curl", "8.7.0", state="imaged", location=s.image("curl", "8.7.0_0")),
            port(4, "zlib", "1.3.1", requested=0, location=s.gone("zlib", "1.3.1_0")),
            port(5, "gnome-themes-standard", "3.27.90", location=s.gone("gnome-themes-standard", "3.27.90_0")),
            port(6, "vim", "9.1.0", variants="+huge", requested_variants="+huge-x11",
                 location=s.gone("vim", "9.1.0_0+huge")),
            port(7, "libiconv", "1.17", state="imaged", requested=0, location=s.image("libiconv", "1.17_0")),
            port(8, "gettext", "0.22.5", requested=0, location=s.image("gettext", "0.22.5_0")),
            port(9, "dbus", "1.14.10", location=s.image("dbus", "1.14.10_0")),
        ], deps=[(1, "zlib"), (6, "ncurses")])
        s.entries = [PortEntry("curl", "8.9.1"), PortEntry("zlib", "1.3.2"), PortEntry("vim", "9.1.0"),
                     PortEntry("gnome-themes-standard", "3.28", replaced_by="adwaita-icon-theme"),
                     PortEntry("libiconv", "1.17"), PortEntry("gettext", "0.22.5"), PortEntry("dbus", "1.14.10")]
        return s

    def test_missing_image_by_row(self):
        s = self.build()
        issues = self.only(self.detect(s.bundle(brew=True)), "ports-missing-image")
        by = {(i.subject, self.step(i)): i for i in issues}
        self.assertEqual(sorted(by, key=str), sorted([("curl", "rebuild"), ("curl", "uninstall@8.8.0_0"),
                                                      ("zlib", "upgrade"), ("gnome-themes-standard", None),
                                                      ("vim", "rebuild")], key=str))
        rebuild = by[("curl", "rebuild")].remedies[0]
        self.assertEqual(rebuild.argv, port_argv(s.prefix, "-n", "-t", "upgrade", "--force", "--no-replace",
                                                 "--no-rev-upgrade", "curl"))
        self.assertEqual((rebuild.on_failure, rebuild.retry_argv),
                         (OnFailure.RETRY_WITH, port_argv(s.prefix, "-t", "install", "--no-rev-upgrade", "curl")))
        vim = by[("vim", "rebuild")].remedies[0]
        self.assertEqual(vim.retry_argv,
                         port_argv(s.prefix, "-t", "install", "--no-rev-upgrade", "vim", "+huge", "-x11"))
        upgrade = by[("zlib", "upgrade")].remedies[0]
        self.assertEqual(upgrade.argv, port_argv(s.prefix, "-n", "-t", "upgrade", "--no-rev-upgrade", "zlib"))
        self.assertIn("from 1.3.1_0 to 1.3.2_0", upgrade.description)
        uninstall = by[("curl", "uninstall@8.8.0_0")]
        self.assertEqual(uninstall.remedies[0].argv, port_argv(s.prefix, "uninstall", "curl", "@8.8.0_0"))
        self.assertEqual((uninstall.confirm_each, uninstall.repairs_install), (True, False))
        self.assertTrue(health.needs_terminal_answer(uninstall))
        self.assertEqual(health.removes_package(uninstall), ("port", "curl"))
        active = by[("curl", "rebuild")]
        self.assertEqual((active.confirm_each, active.repairs_install, active.severity), (True, True, Severity.HIGH))
        self.assertFalse(health.needs_terminal_answer(active))
        self.assertEqual(health.removes_package(active), ("port", "curl"))
        replaced = by[("gnome-themes-standard", None)]
        self.assertIn("replaced by adwaita-icon-theme: reported only", replaced.evidence[-1])
        self.assertEqual((replaced.confirm_each, replaced.repairs_install), (False, False))
        self.assertIsNone(health.removes_package(replaced))

    def test_missing_image_trace_mode_and_undrivable(self):
        s = self.build()
        rebuild = next(i for i in self.detect(s.bundle())
                       if i.code == "ports-missing-image" and self.step(i) == "rebuild")
        self.assertNotIn("-t", rebuild.remedies[0].argv)
        undrivable = s.bundle(s.instance(usability=Usability.PLATFORM_MISMATCH))
        issues = self.only(self.detect(undrivable), "ports-missing-image")
        self.assertEqual(len(issues), 5)
        self.assertTrue(all(not i.remedies for i in issues))
        self.assertTrue(all("no remedy while MacPorts" in i.evidence[-1] for i in issues
                            if i.subject != "gnome-themes-standard"))

    def test_imaged_rows_raise_nothing(self):
        s = self.site([port(1, "curl", "8.9.1")])
        sql(s.portdb, "UPDATE ports SET location = ?", s.image("curl", "8.9.1_0"))
        issues = self.detect(s.bundle())
        self.assertEqual(self.only(issues, "ports-missing-image") + self.only(issues, "ports-inactive-versions"), [])

    def test_inactive_versions_and_imaged_only(self):
        s = self.build()
        issues = self.only(self.detect(s.bundle()), "ports-inactive-versions")
        beside = [i for i in issues if i.remedies]
        self.assertEqual([(i.subject, i.remedies[0].argv[-1]) for i in beside], [("curl", "@8.7.0_0")])
        self.assertEqual(beside[0].remedies[0].action_id, self.id_head(beside[0]) + "uninstall@8.7.0_0")
        self.assertTrue(health.needs_terminal_answer(beside[0]))
        self.assertEqual(beside[0].severity, Severity.LOW)
        listed = [i for i in issues if not i.remedies]
        self.assertEqual([i.subject for i in listed], ["libiconv"])
        self.assertIn("deactivated on purpose", listed[0].evidence[0])
        self.assertFalse(health.needs_terminal_answer(listed[0]))

    def test_unrequested_leaf_active_only(self):
        s = self.build()
        issues = self.only(self.detect(s.bundle()), "ports-unrequested-leaf")
        self.assertEqual([(i.subject, self.argvs(i)) for i in issues],
                         [("gettext", [port_argv(s.prefix, "uninstall", "gettext", "@0.22.5_0")])])
        self.assertTrue(health.needs_terminal_answer(issues[0]))
        self.assertEqual(issues[0].severity, Severity.INFO)
        self.assertEqual(health.removes_package(issues[0]), ("port", "gettext"))

    def test_unrequested_leaf_negative(self):
        s = self.site([port(1, "zlib", "1.3.1", requested=0), port(2, "curl", "8.9.1")], deps=[(2, "zlib")])
        self.assertEqual(self.only(self.detect(s.bundle()), "ports-unrequested-leaf"), [])

    def test_obsolete_port_needs_a_portindex(self):
        s = self.site([port(1, "obsolete-tool", "1.0"), port(2, "curl", "8.9.1")], entries=[PortEntry("curl", "8.9.1")])
        issue = self.one(self.detect(s.bundle()), "ports-obsolete-port")
        self.assertEqual((issue.subject, issue.remedies, issue.severity), ("obsolete-tool", [], Severity.INFO))
        self.assertEqual(self.only(self.detect(s.bundle(index=None)), "ports-obsolete-port"), [])

    def test_replaced_port(self):
        s = self.build()
        issue = self.one(self.detect(s.bundle()), "ports-replaced-port")
        self.assertEqual(issue.subject, "gnome-themes-standard")
        self.assertEqual(self.argvs(issue),
                         [port_argv(s.prefix, "upgrade", "--no-rev-upgrade", "gnome-themes-standard")])
        self.assertIn("with adwaita-icon-theme", issue.remedies[0].description)
        self.assertEqual(health.removes_package(issue), ("port", "gnome-themes-standard"))
        plain = self.site([port(1, "curl", "8.9.1")], entries=[PortEntry("curl", "8.9.1")])
        self.assertEqual(self.only(self.detect(plain.bundle()), "ports-replaced-port"), [])


class FilesTest(HealthTest):
    """Registered files missing on disk, a file below an unreadable directory, and the startup item reloaded"""

    def setUp(self):
        super().setUp()
        self.services: list[model.Service] = []      # set by build()

    def build(self, loaded=False):
        """Make a site whose curl misses registered files, one of them below a directory the user cannot read

        @param loaded  whether curl's startup item is loaded
        @returns       the site
        """
        s = self.site(registry_db=False)
        p = s.prefix
        for rel in ("bin/curl", "lib/libcurl.4.dylib", "bin/dbus-daemon"):
            write(os.path.join(p, rel))
        secret = os.path.join(p, "var", "db", "mysql8-files")
        write(os.path.join(secret, "ibdata1"))
        s.fill([port(1, "curl", "8.9.1", location=s.image("curl", "8.9.1_0")),
                port(2, "dbus", "1.14.10", location=s.image("dbus", "1.14.10_0"))],
               files=[(1, p + "/bin/curl", p + "/bin/curl", 1, 1),
                      (1, p + "/lib/libcurl.4.dylib", p + "/lib/libcurl.4.dylib", 1, 1),
                      (1, p + "/share/man/man1/curl.1", None, 1, 0), (1, p + "/bin/curl/oops", None, 1, 0),
                      (1, secret + "/ibdata1", None, 1, 0), (1, p + "/bin/curl-old", None, 0, 0),
                      (2, p + "/bin/dbus-daemon", None, 1, 1), (2, secret + "/ibdata1", None, 1, 0)])
        os.chmod(secret, 0)
        self.addCleanup(os.chmod, secret, 0o755)
        self.services = [service("org.macports.curl", "/Library/LaunchDaemons/org.macports.curl.plist", p, "curl",
                                 loaded=loaded)]
        return s

    def test_missing_file_and_the_permission_rule(self):
        if os.geteuid() == 0:
            self.skipTest("root reads every directory")
        s = self.build()
        issue = self.one(self.detect(s.bundle(services=self.services)), "ports-missing-file")
        p = s.prefix
        self.assertEqual(issue.subject, "curl")
        self.assertEqual(issue.evidence[0], "2 registered file(s) of curl @8.9.1_0 are missing on disk")
        self.assertEqual(issue.evidence[1:3], [p + "/share/man/man1/curl.1", p + "/bin/curl/oops"])
        self.assertIn("1 file(s) could not be checked", issue.evidence[-1])
        self.assertEqual(self.argvs(issue), [port_argv(p, "-f", "deactivate", "curl", "@8.9.1_0"),
                                             port_argv(p, "-f", "activate", "curl", "@8.9.1_0")])
        self.assertEqual((issue.confirm_each, issue.repairs_install), (True, True))
        self.assertIsNone(health.removes_package(issue))

    def test_missing_file_loads_a_loaded_item(self):
        s = self.build(loaded=True)
        issue = self.one(self.detect(s.bundle(services=self.services)), "ports-missing-file")
        self.assertEqual(issue.remedies[-1].argv, port_argv(s.prefix, "load", "curl"))
        self.assertEqual(issue.remedies[-1].action_id, self.id_head(issue) + "load")
        self.assertIn(s.prefix.replace("/", "%"), issue.remedies[-1].action_id)

    def test_missing_file_without_image_rebuilds(self):
        s = self.build()
        os.unlink(s.gone("curl", "8.9.1_0"))
        issue = self.one(self.detect(s.bundle(services=self.services)), "ports-missing-file")
        self.assertEqual(self.step(issue), "rebuild")
        self.assertIn("--force", issue.remedies[0].argv)
        self.assertEqual(issue.remedies[0].argv[-1], "curl")
        self.assertEqual(health.removes_package(issue), ("port", "curl"))

    def test_missing_file_negative(self):
        s = self.site([port(1, "curl", "8.9.1")], files=[(1, "/bin/sh", None, 1, 0)])
        self.assertEqual(self.only(self.detect(s.bundle()), "ports-missing-file"), [])


class StraysTest(HealthTest):
    """Unregistered files: the removable strays, and the symlinks, extras and other files that are only listed"""

    def setUp(self):
        super().setUp()
        s = self.s = self.site(registry_db=False)
        p = s.prefix
        for rel in ("bin/curl", "bin/stray", "include/foo.h", "lib/libfoo.dylib", "lib/libfoo.dylib.mp_1700000000",
                    "lib/python3.12/__pycache__/x.cpython-312.pyc", "lib/node_modules/left-pad/index.js",
                    "bin/httpie", "share/man/whatis", "share/info/dir", "share/doc/readme.txt",
                    "libexec/macports/lib/thing.tcl", "lib/gdk-pixbuf-2.0/loaders.cache",
                    "Library/Frameworks/Python.framework/Versions/3.12/lib/python3.12/site-packages/x/__init__.py"):
            write(os.path.join(p, rel))
        os.symlink("../Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12",
                   os.path.join(p, "bin", "python3"))
        os.symlink("curl", os.path.join(p, "bin", "oldlink"))
        select = os.path.join(p, "etc", "select", "python3")
        write(os.path.join(select, "base"), "bin/python3\n")
        write(os.path.join(select, "python312"), "${frameworks_dir}/Python.framework/Versions/3.12/bin/python3.12\n")
        os.symlink("python312", os.path.join(select, "current"))
        s.fill([port(1, "curl", "8.9.1", location=s.image("curl", "8.9.1_0")),
                port(2, "foo", "1.0", location=s.image("foo", "1.0_0")),
                port(3, "bar", "1.0", location=s.image("bar", "1.0_0")),
                port(4, "python312", "3.12.7", location=s.image("python312", "3.12.7_0"))],
               files=[(1, p + "/bin/curl", p + "/bin/curl", 1, 1),
                      (2, p + "/lib/libfoo.dylib", p + "/lib/libfoo.dylib.mp_1700000000", 1, 0),
                      (3, p + "/lib/libfoo.dylib", p + "/lib/libfoo.dylib", 1, 0),
                      (4, p + "/etc/select/python3/python312", None, 1, 0)])
        self.extras = {"attributed": [p + "/bin/httpie"],
                       "npm": [{"instance_prefix": p, "name": "left-pad", "path": p + "/lib/node_modules/left-pad"}],
                       "python": [], "gems": [], "cpan": []}

    def test_unregistered_file_removal_and_listing(self):
        p = self.s.prefix
        strays = self.only(self.detect(self.s.bundle(extras=self.extras)), "ports-unregistered-file")
        removable = [i for i in strays if i.remedies]
        self.assertEqual([i.subject for i in removable], [p + "/bin/stray", p + "/include/foo.h"])
        stray = removable[0]
        tar, rm = stray.remedies
        self.assertEqual(tar.argv, [health.TAR, "-cf", "-", "-C", "/", (p + "/bin/stray").lstrip("/")])
        assert self.run_dir is not None
        self.assertEqual(tar.dst, os.path.join(self.run_dir.path, "backup", "strays",
                                               (p + "/bin/stray").replace("/", "%") + ".tar"))
        self.assertEqual((tar.sudo, rm.sudo, rm.argv), (True, True, [RM, p + "/bin/stray"]))
        self.assertEqual((stray.confirm_each, stray.severity), (True, Severity.MEDIUM))
        self.assertTrue(health.needs_terminal_answer(stray))
        self.assertIsNone(health.removes_package(stray))
        listed = [i for i in strays if not i.remedies]
        self.assertEqual(len(listed), 1)
        self.assertEqual(sorted(listed[0].evidence), sorted([
            p + "/bin/httpie (interpreter extras)", p + "/bin/oldlink (symlink)",
            p + "/lib/node_modules/left-pad/index.js (interpreter extras)",
            p + "/share/doc/readme.txt (outside bin, sbin, lib and include)",
            p + "/Library/Frameworks/Python.framework/Versions/3.12/lib/python3.12/site-packages/x/__init__.py "
                "(outside bin, sbin, lib and include)"]))
        self.assertFalse(health.needs_terminal_answer(listed[0]))

    def test_unregistered_file_without_run_or_inventory(self):
        strays = self.only(self.detect(self.s.bundle(extras=self.extras), run_dir=False), "ports-unregistered-file")
        self.assertTrue(strays and all(not i.remedies for i in strays))
        unknown = self.s.instance(inventory_known=False, inventory_error="RegistryDamaged: x")
        found = self.detect(self.s.bundle(unknown, extras=self.extras))
        self.assertEqual(self.only(found, "ports-unregistered-file"), [])

    def test_unregistered_file_negative(self):
        s = self.site([port(1, "curl", "8.9.1")])
        self.assertEqual(self.only(self.detect(s.bundle()), "ports-unregistered-file"), [])

    def test_rubygems_and_cpan_files_of_user_packages_stay(self):
        p = self.s.prefix
        home, perl = p + "/lib/ruby3.2/gems/3.2.0", p + "/lib/perl5/site_perl/5.34"
        arch = perl + "/darwin-thread-multi-2level"
        kept = [home + "/specifications/nokogiri-1.16.0.gemspec", home + "/cache/nokogiri-1.16.0.gem",
                home + "/extensions/arm64-darwin-24/3.2.0/nokogiri-1.16.0/gem.build_complete",
                home + "/extensions/arm64-darwin-24/3.2.0/nokogiri-1.16.0/nokogiri/nokogiri.bundle",
                home + "/doc/nokogiri-1.16.0/ri/created.rid", home + "/build_info/nokogiri-1.16.0.info",
                home + "/plugins/nokogiri_plugin.rb", arch + "/auto/JSON/XS/XS.bundle", arch + "/auto/JSON/XS/XS.bs",
                arch + "/auto/JSON/XS/.packlist", arch + "/auto/Try/Tiny/.packlist"]
        others = [home + "/specifications/rake-13.2.1.gemspec", arch + "/auto/Other/Mod/.packlist"]
        for path in kept + others + [home + "/gems/nokogiri-1.16.0/lib/nokogiri.rb", arch + "/JSON/XS.pm",
                                     perl + "/Try/Tiny.pm"]:
            write(path)
        extras = dict(self.extras,
                      gems=[{"instance_prefix": p, "name": "nokogiri", "version": "1.16.0", "platform": None,
                             "path": home + "/gems/nokogiri-1.16.0"}],
                      cpan=[{"instance_prefix": p, "module": "JSON::XS", "path": arch + "/JSON/XS.pm"},
                            {"instance_prefix": p, "module": "Try::Tiny", "path": perl + "/Try/Tiny.pm"}])
        strays = self.only(self.detect(self.s.bundle(extras=extras)), "ports-unregistered-file")
        removable = [i.subject for i in strays if i.remedies]
        self.assertEqual([path for path in kept if path in removable], [])
        self.assertEqual([path for path in others if path not in removable], [])
        listed = next(i for i in strays if not i.remedies).evidence
        self.assertEqual([path for path in kept if f"{path} (interpreter extras)" not in listed], [])


class LinkageTest(HealthTest):
    """Broken binaries: a missing reference, an architecture gap, and the references that never count"""

    def build(self, refs):
        """Make a site whose curl binary has the references given

        @param refs  the linkage references of the binary
        @returns     the site, the binary and the bundle with its linkage scan
        """
        s = self.site([port(1, "curl", "8.9.1", requested_variants="+http2"), port(2, "zlib", "1.3.1")])
        binary = macho(s.path("bin", "curl"), ARM64)
        linkage = {"binaries": {binary: {"package": f"{s.prefix}|port|curl", "references": refs}}}
        return s, binary, s.bundle(linkage=linkage)

    def test_broken_binaries_missing_reference(self):
        s, binary, bundle = self.build([{"name": "/opt/local/lib/libgone.dylib", "class": "missing",
                                         "resolved": "/opt/local/lib/libgone.dylib"},
                                        {"name": "@rpath/libx.dylib", "class": "unresolved", "resolved": None},
                                        {"name": "/opt/local/lib/libw.dylib", "class": "weak", "resolved": None}])
        issue = self.one(self.detect(bundle), "ports-broken-binaries")
        self.assertEqual(issue.evidence, [f"{binary}: missing /opt/local/lib/libgone.dylib"])
        self.assertEqual(self.argvs(issue), [port_argv(s.prefix, "-n", "upgrade", "--force", "--no-replace",
                                                       "--no-rev-upgrade", "curl")])
        self.assertEqual(issue.remedies[0].retry_argv,
                         port_argv(s.prefix, "install", "--no-rev-upgrade", "curl", "+http2"))
        self.assertEqual((issue.confirm_each, issue.repairs_install), (True, True))
        self.assertEqual(health.removes_package(issue), ("port", "curl"))

    def test_broken_binaries_missing_architecture(self):
        s = self.site([port(1, "curl", "8.9.1")])
        binary = macho(s.path("bin", "curl"), ARM64, X86_64, fat=True)
        lib = macho(s.path("lib", "libz.1.dylib"), X86_64)
        good = macho(s.path("lib", "libok.dylib"), ARM64)
        refs = [{"name": lib, "class": "own", "resolved": lib}, {"name": good, "class": "own", "resolved": good}]
        linkage = {"binaries": {binary: {"package": f"{s.prefix}|port|curl", "references": refs}}}
        issue = self.one(self.detect(s.bundle(linkage=linkage)), "ports-broken-binaries")
        self.assertEqual(issue.evidence, [f"{binary}: {lib} lacks arm64"])

    def test_broken_binaries_negative(self):
        _, _, bundle = self.build([{"name": "/usr/lib/libSystem.B.dylib", "class": "system", "resolved": "/usr/lib"},
                                   {"name": "@rpath/libx.dylib", "class": "unresolved", "resolved": None}])
        self.assertEqual(self.only(self.detect(bundle), "ports-broken-binaries"), [])

    def test_macho_archs(self):
        self.assertEqual(health.macho_archs(macho(self.path("a"), ARM64)), frozenset(["arm64"]))
        self.assertEqual(health.macho_archs(macho(self.path("b"), ARM64, X86_64, fat=True)),
                         frozenset(["arm64", "x86_64"]))
        self.assertIsNone(health.macho_archs(write(self.path("c"), "#!/bin/sh\n")))
        self.assertIsNone(health.macho_archs(self.path("missing")))


class PlatformTest(HealthTest):
    """Ports built for another Darwin major while base matches the host"""

    def test_other_os_counts_active_numeric_majors(self):
        s = self.site([port(1, "curl", "8.9.1", os_major=24), port(2, "fonts", "1.0", os_major="any"),
                       port(3, "zlib", "1.3", state="imaged", os_major=24), port(4, "vim", "9.1", os_major=25)])
        issue = self.one(self.detect(s.bundle()), "ports-built-for-other-os")
        self.assertEqual(issue.evidence[1:], ["curl @8.9.1_0: darwin 24"])
        self.assertEqual(self.argvs(issue), [port_argv(s.prefix, "migrate", "--all"), port_argv(s.prefix, "sync")])
        self.assertEqual((issue.confirm_each, issue.blocks), (True, (Blocks.TARGET,)))

    def test_other_os_negative(self):
        s = self.site([port(1, "curl", "8.9.1", os_major=24)])
        found = self.detect(s.bundle(s.instance(usability=Usability.PLATFORM_MISMATCH)))
        self.assertEqual(self.only(found, "ports-built-for-other-os"), [])
        fine = self.site([port(1, "fonts", "1.0", os_major="any")])
        self.assertEqual(self.only(self.detect(fine.bundle()), "ports-built-for-other-os"), [])

    def test_other_os_without_migrate_is_manual(self):
        s = self.site([port(1, "curl", "8.9.1", os_major=24)], version="2.9.3")
        issue = self.one(self.detect(s.bundle()), "ports-built-for-other-os")
        self.assertEqual(([a.manual for a in issue.remedies], issue.confirm_each), ([True], False))


class ConfigTest(HealthTest):
    """Configuration and environment: the PortIndex age, the macports user, disk usage, settings and PATH"""

    def test_missing_and_stale_portindex(self):
        s = self.site()
        tree = self.path("ports")
        write_sources_conf(s.prefix, f"file://{tree} [default]\n")
        issue = self.one(self.detect(s.bundle()), "ports-stale-portindex")
        self.assertEqual(issue.evidence, [f"{tree}/PortIndex does not exist"])
        self.assertTrue(issue.remedies[0].manual)
        index = write(os.path.join(tree, "PortIndex"))
        old = time.time() - 40 * 86400
        os.utime(index, (old, old))
        self.assertEqual(self.one(self.detect(s.bundle()), "ports-stale-portindex").evidence,
                         [f"{index} is 40 days old"])
        self.assertEqual(self.only(self.detect(s.bundle(), now=old + 86400), "ports-stale-portindex"), [])

    def test_macports_user_dscl_fields(self):
        s = self.site()
        key = (system.DSCL, ".", "-read", "/Users/macports")
        good = (f"NFSHomeDirectory: {s.portdb}/home\nPrimaryGroupID: 501\nRecordName: macports\nUniqueID: 502\n"
                "UserShell: /usr/bin/false\n")
        self.assertEqual(self.only(self.detect(s.bundle(), {key: FakeResponse(stdout=good)}), "ports-macports-user"),
                         [])
        odd = good.replace("UniqueID: 502", "UniqueID: 499").replace("/usr/bin/false", "/bin/sh")
        issue = self.one(self.detect(s.bundle(), {key: FakeResponse(stdout=odd)}), "ports-macports-user")
        self.assertEqual(issue.evidence, ["UniqueID is 499, not a number above 500",
                                          "UserShell is /bin/sh, not /usr/bin/false"])
        missing = self.one(self.detect(s.bundle(), {key: FakeResponse(
            exit=56, stderr="<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n")}), "ports-macports-user")
        self.assertIn("does not exist", missing.evidence[0])
        self.assertTrue(missing.remedies[0].manual)
        self.assertEqual(system.parse_dscl("RecordName:\n macports\n mp\nUniqueID: 502\n"),
                         {"RecordName": "macports mp", "UniqueID": "502"})

    def test_disk_usage_sizes(self):
        s = self.site()
        build, distfiles = os.path.join(s.portdb, "build"), os.path.join(s.portdb, "distfiles")
        os.makedirs(build)
        os.makedirs(distfiles)
        key = (health.DU, "-sk", build, distfiles)
        issue = self.one(self.detect(s.bundle(), {key: FakeResponse(stdout=f"1024\t{build}\n2048\t{distfiles}\n")}),
                         "ports-disk-usage")
        self.assertEqual(issue.evidence, [f"{build}: 1.0 MiB", f"{distfiles}: 2.0 MiB"])
        self.assertTrue(issue.remedies[0].manual)
        self.assertEqual(self.only(self.detect(self.site().bundle()), "ports-disk-usage"), [])

    def test_settings_against_archive_defaults(self):
        s = self.site(conf={"prefix": "/opt/local", "frameworks_dir": "/opt/local/Library/Frameworks",
                            "applications_dir": "/Applications/MacPorts-Test", "buildfromsource": "always",
                            "delete_la_files": "no"})
        issue = self.one(self.detect(s.bundle()), "ports-no-binary-archives")
        self.assertEqual(issue.evidence[:3], ["applications_dir /Applications/MacPorts-Test (binary archives are "
                                              "built for /Applications/MacPorts)",
                                              "delete_la_files no (binary archives use yes)", "buildfromsource always"])
        self.assertEqual(issue.remedies, [])
        plain = self.site(conf={"prefix": "/opt/local", "frameworks_dir": "/opt/local/Library/Frameworks"})
        self.assertEqual(self.only(self.detect(plain.bundle()), "ports-no-binary-archives"), [])

    def test_not_on_path(self):
        s = self.site()
        bin_dir = s.path("bin")
        with_bin = {"live": {"PATH": [{"text": "/usr/bin", "path": "/usr/bin"}, {"text": bin_dir, "path": bin_dir}]}}
        self.assertEqual(self.only(self.detect(s.bundle(environment=with_bin)), "ports-not-on-path"), [])
        without = {"live": {"PATH": [{"text": "/usr/bin", "path": "/usr/bin"}]}}
        issue = self.one(self.detect(s.bundle(environment=without)), "ports-not-on-path")
        self.assertEqual((issue.subject, issue.title), (bin_dir, f"PATH lacks {bin_dir}"))
        self.assertTrue(issue.remedies[0].manual)
        self.assertEqual(self.only(self.detect(s.bundle(environment={})), "ports-not-on-path"), [])

    def test_usr_local_cellar(self):
        cellar = self.path("usr-local", "Cellar")
        os.makedirs(cellar)
        issue = self.one(self.detect(self.site().bundle(), cellar=cellar), "ports-usr-local-cellar")
        self.assertEqual((issue.subject, issue.instance_prefix, issue.severity), (cellar, None, Severity.INFO))
        self.assertEqual(self.only(self.detect(self.site().bundle()), "ports-usr-local-cellar"), [])


class StartupItemsTest(HealthTest):
    """Dangling owned plists, and a selected `port select` option that no active port provides"""

    def test_dangling_plists(self):
        s = self.site([port(1, "foo", "1.0"), port(2, "bar", "1.0")])
        daemons = self.path("LaunchDaemons")
        os.makedirs(daemons)
        link = os.path.join(daemons, "org.macports.foo.plist")
        os.symlink(s.path("etc", "LaunchDaemons", "org.macports.foo", "org.macports.foo.plist"), link)
        agent = write(self.path("LaunchAgents", "org.macports.bar.plist"))
        daemondo = write(s.path("bin", "daemondo"))
        services = [service("org.macports.foo", link, s.prefix, "foo"),
                    service("org.macports.bar", agent, s.prefix, "bar", scope="user", program=s.path("bin", "gone")),
                    service("org.macports.ok", agent, s.prefix, "bar", scope="user", program=daemondo),
                    service("com.example.job", link, s.prefix, None, owned=False)]
        issues = self.only(self.detect(s.bundle(services=services)), "ports-dangling-plist")
        self.assertEqual([i.subject for i in issues], ["org.macports.foo", "org.macports.bar"])
        dangling_link, gone_program = issues
        self.assertEqual([(a.argv, a.sudo, a.on_failure) for a in dangling_link.remedies],
                         [([env_services.LAUNCHCTL, "bootout", "system/org.macports.foo"], True, OnFailure.PROBE),
                          ([RM, link], True, OnFailure.STOP)])
        self.assertEqual([(a.argv, a.sudo) for a in gone_program.remedies],
                         [([env_services.LAUNCHCTL, "bootout", "gui/501/org.macports.bar"], False),
                          ([RM, agent], True)])
        self.assertEqual((dangling_link.confirm_each, dangling_link.severity), (True, Severity.LOW))
        self.assertEqual(self.only(self.detect(s.bundle(services=services[2:])), "ports-dangling-plist"), [])

    def test_selected_option_not_installed(self):
        s = self.site([port(1, "gcc14", "14.2.0"), port(2, "python311", "3.11.9", state="imaged")])
        p = s.prefix
        python = os.path.join(p, "etc", "select", "python3")
        write(os.path.join(python, "base"), "bin/python3\n")
        os.symlink("python311", os.path.join(python, "current"))
        gcc = os.path.join(p, "etc", "select", "gcc")
        write(os.path.join(gcc, "base"), "bin/gcc\n")
        write(os.path.join(gcc, "mp-gcc14"), "bin/gcc-mp-14\n")
        os.symlink("mp-gcc14", os.path.join(gcc, "current"))
        llvm = os.path.join(p, "etc", "select", "llvm")
        write(os.path.join(llvm, "base"), "bin/clang\n")
        os.symlink("none", os.path.join(llvm, "current"))
        sql(s.portdb, "INSERT INTO files (id, path, actual_path, active, binary) VALUES (1, ?, NULL, 1, 0)",
            os.path.join(gcc, "mp-gcc14"))
        issue = self.one(self.detect(s.bundle()), "ports-missing-selection")
        self.assertEqual(issue.subject, "python3")
        self.assertIn("python311, whose option file is gone", issue.evidence[0])
        self.assertEqual(self.argvs(issue), [port_argv(p, "select", "--set", "python3", "none")])
        self.assertEqual((issue.remedies[0].manual, issue.confirm_each), (True, False))


class InterfaceTest(unittest.TestCase):
    """What `doctor --fix` reads of a finding: the terminal answer, the removed package, the repairs and the ids"""

    def issue(self, code, remedies=(), subject="curl"):
        """Return a LOW finding at /opt/local that asks before each item

        @param code      the finding's code
        @param remedies  the remedies
        @param subject   the port the finding is about
        @returns         the finding
        """
        return model.Issue(code=code, severity=Severity.LOW, title="", subject=subject, instance_prefix="/opt/local",
                           evidence=[], remedies=list(remedies), auto_fix=False, confirm_each=True,
                           repairs_install=False, blocks=())

    def test_no_remedy_needs_no_answer_and_removes_nothing(self):
        for code in ("ports-inactive-versions", "ports-unrequested-leaf", "ports-unregistered-file",
                     "ports-missing-image"):
            self.assertFalse(health.needs_terminal_answer(self.issue(code)))
            self.assertIsNone(health.removes_package(self.issue(code)))
        self.assertIsNone(health.removes_package(self.issue("ports-built-for-other-os")))
        self.assertEqual(health.MANAGER_REPAIRS, ("ports-platform-mismatch", "ports-built-for-other-os",
                                                  "ports-registry-schema-update", "ports-cannot-run"))

    def test_action_ids(self):
        self.assertEqual(health.action_id("ports-unregistered-file", "/opt/local/bin/x", "rm"),
                         "doctor.ports-unregistered-file.%opt%local%bin%x.rm")


if __name__ == "__main__":
    unittest.main()

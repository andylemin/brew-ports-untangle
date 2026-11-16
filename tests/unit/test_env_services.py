"""launchd plists of both managers: Homebrew services and MacPorts startup items"""

import os
import plistlib
import sqlite3
import unittest
from typing import Any

from brew_ports import model, runner as r
from brew_ports.env import services as s
from tests.unit.helpers import make_package
from tests.unit.test_env_paths import EnvTest, fixture

UID = 501
NOT_FOUND = r.FakeResponse(exit=113, stderr='Bad request.\nCould not find service "x" in domain for user gui: 501\n')


def printed(domain, label, plist, program, *, pid=None, datadir="/nonexistent"):
    """Return a `launchctl print` key and its response, for a stopped job or a running one

    @param domain   the launchd domain
    @param label    the job's label
    @param plist    the job's plist
    @param program  the job's program
    @param pid      the running job's pid; None for a stopped job
    @param datadir  the data directory the running job's arguments name
    @returns        the argv and the fake response
    """
    if pid is None:
        text = fixture("launchctl-print-stopped.txt", DOMAIN=domain, LABEL=label, PLIST=plist, PROGRAM=program)
    else:
        text = fixture("launchctl-print-running.txt", DOMAIN=domain, LABEL=label, PLIST=plist, PROGRAM=program,
                       PID=str(pid), DATADIR=datadir)
    return (s.LAUNCHCTL, "print", f"{domain}/{label}"), r.FakeResponse(stdout=text)


class ServicesTest(EnvTest):
    """The base of the service tests: a home, the three launchd directories and three instances"""

    def setUp(self):
        super().setUp()
        self.home = self.path("Users", "alice")
        self.agents = os.path.join(self.home, "Library", "LaunchAgents")
        self.sys_agents = self.path("Library", "LaunchAgents")
        self.daemons = self.path("Library", "LaunchDaemons")
        self.mkdirs(self.agents, self.sys_agents, self.daemons)
        self.brew = self.instance(model.Manager.BREW, "opt/homebrew")
        self.intel = self.usr_local()
        self.ports = self.instance(model.Manager.PORTS, "opt/local")

    def dirs(self):
        """Return the test's launchd directories, each with the managers whose rules apply there

        @returns  the user's agents, the system agents and the system daemons
        """
        return [s.LaunchDir(self.agents, "user", ("brew",)), s.LaunchDir(self.sys_agents, "user", ("ports",)),
                s.LaunchDir(self.daemons, "system", ("brew", "ports"))]

    def plist(self, directory, name, **data):
        """Write a plist

        @param directory  the directory, made when missing
        @param name       the file's name
        @param data       the plist's keys and values
        @returns          the plist's path
        """
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name)
        with open(path, "wb") as fh:
            plistlib.dump(data, fh)
        return path

    def program(self, inst, rel):
        """Write an executable script in an instance's prefix

        @param inst  the instance
        @param rel   the script's path below the prefix, with `/` separators
        @returns     the script's path
        """
        return self.touch(os.path.join(inst.prefix, *rel.split("/")), b"#!/bin/sh\n", 0o755)

    def scan(self, responses, packages=(), labels=None, owner_of=None, **kw):
        """Inspect the services of the three instances on a fake runner that finds no other job

        @param responses  the canned `launchctl print` responses, by argv
        @param packages   the installed packages
        @param labels     launchd labels to formulae; None for none
        @param owner_of   returns the port that registered a path, or None
        @param kw         further options of `inspect`
        @returns          the scan and the fake runner
        """
        fake = self.runner(responses, default=NOT_FOUND)
        result = s.inspect(fake, [self.brew, self.intel, self.ports], list(packages), service_labels=labels or {},
                           owner_of=owner_of, home=self.home, uid=UID, directories=self.dirs(), **kw)
        return result, fake

    def by_label(self, result):
        """Return a scan's services by label

        @param result  the scan
        @returns       each service, by its label
        """
        return {svc.label: svc for svc in result.services}


class AttributionTest(ServicesTest):
    """Tests of the attribution of plists to instances, packages and loaded jobs"""

    def test_labels_across_two_prefixes_sharing_launch_agents(self):
        mysqld = self.program(self.intel, "opt/mysql/bin/mysqld_safe")
        datadir = os.path.join(self.intel.prefix, "var", "mysql")
        self.mkdirs(datadir)
        mysql = self.plist(self.agents, "homebrew.mxcl.mysql.plist", Label="homebrew.mxcl.mysql",
                           ProgramArguments=[mysqld, "--datadir=" + datadir])
        redisd = self.program(self.brew, "opt/redis/bin/redis-server")
        redis = self.plist(self.agents, "sh.brew.redis.plist", Label="sh.brew.redis", ExitTimeOut=60,
                           ProgramArguments=[redisd, os.path.join(self.brew.prefix, "etc", "redis.conf")])
        responses = dict([printed("gui/501", "homebrew.mxcl.mysql", mysql, mysqld, pid=4242, datadir=datadir),
                          printed("user/501", "sh.brew.redis", redis, redisd)])
        result, fake = self.scan(responses)
        got = self.by_label(result)
        self.assertEqual(sorted(got), ["homebrew.mxcl.mysql", "sh.brew.redis"])
        m = got["homebrew.mxcl.mysql"]
        self.assertEqual((m.instance_prefix, m.package, m.package_kind, m.owned),
                         (self.intel.prefix, "mysql", "formula", True))
        self.assertEqual((m.loaded, m.running, m.pid, m.domain, m.scope), (True, True, 4242, "gui/501", "user"))
        self.assertEqual(m.data_dirs, [datadir])
        self.assertEqual(m.exit_timeout_s, 20)
        rd = got["sh.brew.redis"]
        self.assertEqual((rd.instance_prefix, rd.package, rd.loaded, rd.running, rd.pid, rd.domain),
                         (self.brew.prefix, "redis", True, False, None, "user/501"))
        self.assertEqual(rd.exit_timeout_s, 60)
        self.assertIn((s.LAUNCHCTL, "print", "gui/501/sh.brew.redis"), fake.calls)   # gui first, then user

    def test_a_kept_plist_beside_another_prefixs_loaded_job(self):
        old = self.program(self.intel, "opt/mysql/bin/mysqld_safe")
        kept = self.plist(self.agents, "homebrew.mxcl.mysql.plist", Label="homebrew.mxcl.mysql", Program=old)
        keg = os.path.join(self.brew.prefix, "Cellar", "mysql", "9.0")
        new = self.touch(os.path.join(keg, "bin", "mysqld_safe"), b"#!/bin/sh\n", 0o755)
        os.makedirs(os.path.join(self.brew.prefix, "opt"))
        os.symlink(keg, os.path.join(self.brew.prefix, "opt", "mysql"))
        mysqld = os.path.join(self.brew.prefix, "opt", "mysql", "bin", "mysqld_safe")
        keg_plist_real = self.plist(keg, "homebrew.mxcl.mysql.plist", Label="homebrew.mxcl.mysql",
                                    ProgramArguments=[mysqld])
        keg_plist = os.path.join(self.brew.prefix, "opt", "mysql", "homebrew.mxcl.mysql.plist")
        responses = dict([printed("gui/501", "homebrew.mxcl.mysql", keg_plist,
                                  os.path.join(self.brew.prefix, "opt", "mysql", "bin", "mysqld_safe"), pid=77)])
        packages = [make_package("mysql", prefix=self.brew.prefix, version="9.0"),
                    make_package("mysql", prefix=self.intel.prefix, version="8.0")]
        result, _ = self.scan(responses, packages)
        source = [x for x in result.services if x.plist == kept]
        target = [x for x in result.services if x.plist == keg_plist]
        self.assertEqual(len(source), 1)
        self.assertEqual((source[0].instance_prefix, source[0].loaded, source[0].domain, source[0].pid),
                         (self.intel.prefix, False, None, None))
        self.assertEqual(len(target), 1)
        self.assertEqual((target[0].instance_prefix, target[0].loaded, target[0].pid, target[0].owned,
                          target[0].package, target[0].scope), (self.brew.prefix, True, 77, True, "mysql", "user"))
        self.assertTrue(os.path.samefile(keg_plist, keg_plist_real))
        self.assertTrue(new)

    def test_unknown_or_no_program_is_unattributed(self):
        self.plist(self.agents, "com.example.agent.plist", Label="com.example.agent",
                   Program="/Applications/Example.app/Contents/MacOS/agent")
        self.plist(self.agents, "com.example.empty.plist", Label="com.example.empty", RunAtLoad=True)
        result, fake = self.scan({})
        self.assertEqual(result.services, [])
        self.assertEqual(sorted(os.path.basename(p) for p in result.unattributed),
                         ["com.example.agent.plist", "com.example.empty.plist"])
        self.assertFalse([c for c in fake.calls if c[0] == s.LAUNCHCTL])

    def test_a_failed_registry_lookup_skips_only_that_plist(self):
        self.plist(self.daemons, "org.macports.redis.plist", Label="org.macports.redis",
                   Program=self.program(self.ports, "bin/redis-server"))

        def broken(_path):
            raise sqlite3.OperationalError("database disk image is malformed")

        result, _ = self.scan({}, owner_of=broken)
        self.assertEqual([os.path.basename(i.path) for i in result.unreadable], ["org.macports.redis.plist"])
        self.assertIn("OperationalError", result.unreadable[0].error)

    def test_an_interrupt_during_attribution_stops_the_scan(self):
        self.plist(self.daemons, "org.macports.redis.plist", Label="org.macports.redis",
                   Program=self.program(self.ports, "bin/redis-server"))

        def interrupted(_path):
            raise r.Interrupted("SIGINT")

        with self.assertRaises(r.Interrupted):
            self.scan({}, owner_of=interrupted)

    def test_bad_plists_are_listed_and_skipped(self):
        self.touch(os.path.join(self.agents, "garbage.plist"), b"\x00\x01 not a plist")
        with open(os.path.join(self.agents, "array.plist"), "wb") as fh:
            plistlib.dump(["/opt/homebrew/bin/x"], fh)
        locked = self.plist(self.daemons, "com.example.locked.plist", Label="com.example.locked",
                            Program=self.program(self.brew, "bin/locked"))
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o644)
        result, _ = self.scan({})
        names = sorted(os.path.basename(i.path) for i in result.unreadable)
        expected = ["array.plist", "garbage.plist"]
        if os.geteuid() != 0:          # root reads a mode-0 file
            expected.insert(1, "com.example.locked.plist")
        self.assertEqual(names, expected)
        self.assertTrue(all(not i.readable and i.error for i in result.unreadable))
        self.assertIn("not a dict", [i for i in result.unreadable if i.path.endswith("array.plist")][0].error)
        self.assertEqual([x for x in result.services if not x.plist.endswith("locked.plist")], [])

    def test_a_user_job_running_a_manager_binary(self):
        rsync = self.program(self.brew, "bin/rsync")
        job = self.plist(self.agents, "com.alice.backup.plist", Label="com.alice.backup",
                         ProgramArguments=[rsync, "-a", self.home, "/Volumes/Backup"])
        ports_program = self.program(self.ports, "bin/foo")
        self.plist(self.agents, "sh.brew.foo.plist", Label="sh.brew.foo", Program=ports_program)
        result, _ = self.scan({})
        got = self.by_label(result)
        backup = got["com.alice.backup"]
        self.assertEqual((backup.owned, backup.package, backup.package_kind, backup.instance_prefix, backup.loaded),
                         (False, None, None, self.brew.prefix, False))
        self.assertEqual(result.program(job), rsync)
        # A Homebrew label whose program lies under MacPorts is that user's own job.
        self.assertEqual((got["sh.brew.foo"].owned, got["sh.brew.foo"].instance_prefix), (False, self.ports.prefix))

    def test_service_name_args_label_and_jenkins_lts(self):
        dbus = self.program(self.brew, "opt/dbus/bin/dbus-daemon")
        self.plist(self.agents, "org.freedesktop.dbus-session.plist", Label="org.freedesktop.dbus-session",
                   ProgramArguments=[dbus, "--nofork", "--session"])
        java = self.program(self.brew, "opt/openjdk@21/bin/java")
        self.plist(self.agents, "sh.brew.jenkins-lts.plist", Label="sh.brew.jenkins-lts",
                   ProgramArguments=[java, "-jar", os.path.join(self.brew.prefix, "opt", "jenkins-lts", "libexec",
                                                                "jenkins.war")])
        result, _ = self.scan({}, labels={"org.freedesktop.dbus-session": "dbus"})
        got = self.by_label(result)
        self.assertEqual((got["org.freedesktop.dbus-session"].package, got["org.freedesktop.dbus-session"].owned),
                         ("dbus", True))
        self.assertEqual((got["sh.brew.jenkins-lts"].package, got["sh.brew.jenkins-lts"].owned), ("jenkins-lts", True))

    def test_the_old_label_of_a_renamed_formula(self):
        postgres = self.program(self.brew, "opt/postgresql/bin/postgres")
        plist = self.plist(self.agents, "homebrew.mxcl.postgresql.plist", Label="homebrew.mxcl.postgresql",
                           ProgramArguments=[postgres, "-D", os.path.join(self.brew.prefix, "var", "postgres")])
        # The labels the catalogue gives a renamed formula, its old ones included (test_homebrew_catalogue).
        labels = {"homebrew.mxcl.postgresql@14": "postgresql@14", "homebrew.mxcl.postgresql": "postgresql@14"}
        pkg = make_package("postgresql@14", prefix=self.brew.prefix)
        result, _ = self.scan(dict([printed("gui/501", "homebrew.mxcl.postgresql", plist, postgres, pid=7)]), [pkg],
                              labels=labels)
        svc = self.by_label(result)["homebrew.mxcl.postgresql"]
        self.assertEqual((svc.owned, svc.package, svc.package_kind, svc.running),
                         (True, "postgresql@14", "formula", True))
        s.attach(result.services, [pkg])
        self.assertEqual([x.label for x in pkg.services], ["homebrew.mxcl.postgresql"])

    def test_a_label_naming_no_installed_formula_goes_by_the_keg(self):
        keg = os.path.join(self.brew.prefix, "Cellar", "postgresql", "14.15")   # a rack left under the old name
        postgres = self.touch(os.path.join(keg, "bin", "postgres"), b"", 0o755)
        self.plist(self.agents, "homebrew.mxcl.postgresql.plist", Label="homebrew.mxcl.postgresql", Program=postgres)
        self.plist(self.agents, "sh.brew.redis.plist", Label="sh.brew.redis", Program=postgres)
        result, _ = self.scan({}, racks={self.brew.prefix: {"postgresql": "postgresql@14", "redis": "redis"}})
        got = self.by_label(result)
        self.assertEqual((got["homebrew.mxcl.postgresql"].package, got["homebrew.mxcl.postgresql"].owned),
                         ("postgresql@14", True))
        self.assertEqual(got["sh.brew.redis"].package, "redis")
        self.assertEqual(s.keg_rack(self.brew.prefix, postgres), "postgresql")
        self.assertIsNone(s.keg_rack(self.brew.prefix, os.path.join(self.brew.prefix, "bin", "brew")))

    def test_a_brew_services_run_job_of_the_keg(self):
        keg = os.path.join(self.brew.prefix, "Cellar", "mariadb", "11.8")
        self.touch(os.path.join(keg, "bin", "mariadbd-safe"), b"", 0o755)
        os.makedirs(os.path.join(self.brew.prefix, "opt"))
        os.symlink(keg, os.path.join(self.brew.prefix, "opt", "mariadb"))
        program = os.path.join(self.brew.prefix, "opt", "mariadb", "bin", "mariadbd-safe")
        self.plist(keg, "sh.brew.mariadb.plist", Label="sh.brew.mariadb", ProgramArguments=[program])
        keg_plist = os.path.join(self.brew.prefix, "opt", "mariadb", "sh.brew.mariadb.plist")
        responses = dict([printed("gui/501", "sh.brew.mariadb", keg_plist, program, pid=31)])
        packages = [make_package("mariadb", prefix=self.brew.prefix, version="11.8"),
                    make_package("wget", prefix=self.brew.prefix, version="1.0")]
        result, fake = self.scan(responses, packages)
        self.assertEqual(len(result.services), 1)
        svc = result.services[0]
        self.assertEqual((svc.plist, svc.loaded, svc.running, svc.pid, svc.owned, svc.package, svc.instance_prefix),
                         (keg_plist, True, True, 31, True, "mariadb", self.brew.prefix))
        # A keg label is probed in every domain: a job may be loaded as the user and as root.
        for domain in ("gui/501", "user/501", "system"):
            self.assertIn((s.LAUNCHCTL, "print", f"{domain}/sh.brew.mariadb"), fake.calls)
        self.assertNotIn((s.LAUNCHCTL, "print", "gui/501/sh.brew.wget"), fake.calls)

    def test_a_loaded_job_of_an_unknown_program_is_only_a_note(self):
        keg = os.path.join(self.brew.prefix, "Cellar", "redis", "8.0")
        program = self.touch(os.path.join(keg, "bin", "redis-server"), b"", 0o755)
        self.plist(keg, "sh.brew.redis.plist", Label="sh.brew.redis", Program=program)
        responses = dict([printed("gui/501", "sh.brew.redis", "/tmp/elsewhere.plist", "/tmp/redis-server", pid=5)])
        result, _ = self.scan(responses, [make_package("redis", prefix=self.brew.prefix, version="8.0")])
        self.assertEqual(result.services, [])
        self.assertTrue(any("no plist of that label" in n for n in result.notes))


class MacPortsTest(ServicesTest):
    """Tests of the MacPorts startup items: links into the prefix, labels and registered plists"""

    def test_startup_item_links_labels_and_edits(self):
        etc = os.path.join(self.ports.prefix, "etc", "LaunchDaemons", "org.macports.mysql8")
        daemondo = self.program(self.ports, "bin/daemondo")
        target = self.plist(etc, "org.macports.mysql8.plist", Label="org.macports.mysql8",
                            ProgramArguments=[daemondo, "--label=mysql8", "--start-cmd",
                                              os.path.join(etc, "mysql8.wrapper"), "start", ";", "--pid=none"])
        link = os.path.join(self.daemons, "org.macports.mysql8.plist")
        os.symlink(target, link)
        dbus_daemon = self.program(self.ports, "bin/dbus-daemon")
        dbus = self.plist(self.daemons, "org.freedesktop.dbus-system.plist", Label="org.freedesktop.dbus-system",
                          ProgramArguments=[dbus_daemon, "--system", "--nofork"])
        edited = self.plist(self.daemons, "org.macports.edited.plist", Label="org.macports.edited",
                            Program=self.program(self.ports, "sbin/edited"))
        agent_etc = os.path.join(self.ports.prefix, "etc", "LaunchAgents", "org.macports.gone")
        os.makedirs(agent_etc)
        dangling = os.path.join(self.sys_agents, "org.macports.gone.plist")
        os.symlink(os.path.join(agent_etc, "org.macports.gone.plist"), dangling)
        registry = {link: "mysql8-server", target: "mysql8-server", dbus: "dbus"}
        responses = dict([printed("system", "org.macports.mysql8", link, daemondo, pid=99)])
        result, _ = self.scan(responses, owner_of=registry.get)
        got = self.by_label(result)
        mysql = got["org.macports.mysql8"]
        self.assertEqual((mysql.owned, mysql.package, mysql.package_kind, mysql.scope, mysql.domain, mysql.pid,
                          mysql.instance_prefix), (True, "mysql8-server", "port", "system", "system", 99,
                                                   self.ports.prefix))
        self.assertEqual(mysql.plist, link)
        self.assertEqual((got["org.freedesktop.dbus-system"].owned, got["org.freedesktop.dbus-system"].package),
                         (True, "dbus"))
        self.assertEqual((got["org.macports.edited"].owned, got["org.macports.edited"].package), (False, None))
        self.assertEqual(edited, got["org.macports.edited"].plist)
        gone = got["org.macports.gone"]
        self.assertEqual((gone.owned, gone.package, gone.scope, gone.loaded, gone.instance_prefix),
                         (True, "gone", "user", False, self.ports.prefix))
        self.assertIn(dangling, [i.path for i in result.unreadable])

    def test_a_registered_plist_outside_the_etc_tree(self):
        program = self.program(self.ports, "bin/prometheus")
        plist = self.plist(self.daemons, "org.macports.prometheus.plist", Label="org.macports.prometheus",
                           Program=program)
        result, _ = self.scan({}, owner_of={plist: "prometheus"}.get)
        svc = self.by_label(result)["org.macports.prometheus"]
        self.assertEqual((svc.owned, svc.package, svc.loaded), (True, "prometheus", False))


class PiecesTest(ServicesTest):
    """Tests of the plist readers, the data directories, `launchctl print` and the refresh"""

    def test_program_rule(self):
        self.assertEqual(s.program_of({"Program": "/x"}), "/x")
        self.assertEqual(s.program_of({"ProgramArguments": ["/y", "-a"]}), "/y")
        self.assertEqual(s.program_of({"Program": 5, "ProgramArguments": ["/z"]}), "/z")
        self.assertIsNone(s.program_of({"ProgramArguments": []}))
        self.assertIsNone(s.program_of({"ProgramArguments": [1, "/w"]}))
        self.assertIsNone(s.program_of({"ProgramArguments": "/v"}))
        self.assertEqual(s.arguments_of({"Program": "/x", "ProgramArguments": ["x", 3, "--a=/b"]}),
                         ["/x", "x", "--a=/b"])

    def test_exit_timeout(self):
        for value, expected in ((60, 60), (0, 0), (None, 20), (True, 20), ("30", 20), (-1, 20)):
            data = {} if value is None else {"ExitTimeOut": value}
            self.assertEqual(s.exit_timeout_of(data), expected, value)

    def test_data_dirs(self):
        prefix = self.brew.prefix
        var = os.path.join(prefix, "var")
        made = [os.path.join(var, n) for n in ("mysql", "mysql@8.4", os.path.join("lib", "mysql"),
                                                os.path.join("db", "mysql"), os.path.join("db", "mysql-files"),
                                                os.path.join("lib", "mysql-data"), os.path.join("db", "other"))]
        self.mkdirs(*made, os.path.join(prefix, "etc", "mysql"), os.path.join(var, "run"))
        args = [os.path.join(prefix, "bin", "mysqld"), "--datadir=" + os.path.join(var, "lib", "mysql-data") + "/",
                "--pid-file=" + os.path.join(var, "run", "mysqld.pid"), os.path.join(var, "db", "other"),
                "--defaults-file=" + os.path.join(prefix, "etc", "mysql"), "--datadir=" + os.path.join(var, "mysql")]
        self.assertEqual(s.data_dirs(prefix, "mysql", args), made)
        self.assertEqual(s.data_dirs(prefix, None, ["--datadir=" + os.path.join(var, "mysql")]),
                         [os.path.join(var, "mysql")])
        self.assertEqual(s.data_dirs(self.path("nowhere"), "mysql", []), [])

    def test_parse_print(self):
        text = fixture("launchctl-print-running.txt", DOMAIN="gui/501", LABEL="sh.brew.x", PLIST="/p/sh.brew.x.plist",
                       PROGRAM="/opt/homebrew/opt/x/bin/x", PID="123", DATADIR="/opt/homebrew/var/x")
        job = s.parse_print(text, "gui/501", "sh.brew.x")
        self.assertEqual((job.path, job.program, job.pid, job.state, job.running),
                         ("/p/sh.brew.x.plist", "/opt/homebrew/opt/x/bin/x", 123, "running", True))
        self.assertEqual(job.arguments, ["/opt/homebrew/opt/x/bin/x", "--datadir=/opt/homebrew/var/x"])
        stopped = s.parse_print(fixture("launchctl-print-stopped.txt", DOMAIN="user/501", LABEL="y", PLIST="/p",
                                        PROGRAM="/q"), "user/501", "y")
        self.assertEqual((stopped.pid, stopped.state, stopped.running), (None, "not running", False))

    def test_refresh_rechecks_the_job(self):
        program = self.program(self.brew, "opt/redis/bin/redis-server")
        plist = self.plist(self.agents, "sh.brew.redis.plist", Label="sh.brew.redis", Program=program)
        svc = model.Service("sh.brew.redis", plist, "user", "gui/501", True, True, 10, 20, True, [], "redis",
                            "formula", self.brew.prefix)
        gone = s.refresh(self.runner({}, default=NOT_FOUND), svc, UID)
        self.assertEqual((gone.loaded, gone.running, gone.pid, gone.domain), (False, False, None, None))
        back = s.refresh(self.runner(dict([printed("user/501", "sh.brew.redis", plist, program, pid=11)]),
                                     default=NOT_FOUND), gone, UID)
        self.assertEqual((back.loaded, back.pid, back.domain), (True, 11, "user/501"))
        other = s.refresh(self.runner(dict([printed("gui/501", "sh.brew.redis", "/x", "/elsewhere/redis", pid=12)]),
                                      default=NOT_FOUND), svc, UID)
        self.assertFalse(other.loaded)

    def test_corroborate_attach_and_collect(self):
        program = self.program(self.brew, "opt/redis/bin/redis-server")
        plist = self.plist(self.agents, "sh.brew.redis.plist", Label="sh.brew.redis", Program=program)
        pkg = make_package("redis", prefix=self.brew.prefix)
        fake = self.runner({}, default=NOT_FOUND)
        entries: list[Any] = [{"name": "redis", "status": "started", "file": plist},
                              {"name": "mariadb", "status": "none", "file": "/x/sh.brew.mariadb.plist"},
                              {"name": "pg", "status": "started", "file": "/x/sh.brew.pg.plist"}, "junk"]
        result = s.inspect(fake, [self.brew], [pkg], service_labels={}, owner_of=None, home=self.home, uid=UID,
                           directories=self.dirs(), brew_services={self.brew.prefix: entries})
        self.assertEqual(len(result.notes), 1)
        self.assertIn("sh.brew.pg.plist", result.notes[0])
        s.attach(result.services, [pkg])
        s.attach(result.services, [pkg])
        self.assertEqual([x.label for x in pkg.services], ["sh.brew.redis"])
        listed = s.collect(fake, [self.brew], [], service_labels={}, owner_of=None, home=self.home, uid=UID,
                           directories=self.dirs())
        self.assertEqual([x.label for x in listed], ["sh.brew.redis"])

    def test_default_directories(self):
        dirs = s.launch_dirs("/Users/alice")
        self.assertEqual([(d.path, d.scope) for d in dirs],
                         [("/Users/alice/Library/LaunchAgents", "user"), ("/Library/LaunchAgents", "user"),
                          ("/Library/LaunchDaemons", "system")])
        self.assertEqual(s.homebrew_formula("homebrew.mxcl.python@3.12", {}), "python@3.12")
        self.assertIsNone(s.homebrew_formula("sh.brew.", {}))
        self.assertIsNone(s.homebrew_formula("org.macports.x", {}))


if __name__ == "__main__":
    unittest.main()

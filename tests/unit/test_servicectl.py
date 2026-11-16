"""Stopping and waiting, restarting in the recorded domain, and deleting plists"""

import os
import unittest
from unittest import mock

from brew_ports import runner as r, servicectl, system
from brew_ports.model import Manager
from tests.unit.fixtures.doctor import builders as b
from tests.unit.helpers import TempDirTest, make_instance

LABEL = "sh.brew.mysql"


class ServiceTest(TempDirTest):
    """The base of the service tests: a Homebrew mysql service loaded in `gui/501`, and a fake clock"""

    def setUp(self):
        super().setUp()
        self.prefix = self.path("opt", "homebrew")
        self.program = os.path.join(self.prefix, "opt", "mysql", "bin", "mysqld_safe")
        self.plist = b.write_plist(self.path("Users", "alice", "Library", "LaunchAgents", LABEL + ".plist"), LABEL,
                                   self.program, ExitTimeOut=5)
        self.svc = b.service(LABEL, self.plist, self.prefix, "mysql", domain="gui/501", loaded=True, pid=4242,
                             exit_timeout_s=5, data_dirs=[self.path("opt", "homebrew", "var", "mysql")])
        self.clock = b.FakeClock()

    def runner(self, responses):
        """Return a fake runner on which every command not listed finds no launchd job

        @param responses  the canned responses, by argv
        @returns          the runner
        """
        return r.FakeRunner(responses=responses, default=b.NOT_FOUND, console=b.QuietConsole(), environ={},
                            out_dir=self.path("out"))

    def stop(self, fake, services=None, alive=lambda pid: False):
        """Stop services as phase 5 does, on the fake clock

        @param fake      the fake runner
        @param services  the services; None for the mysql service
        @param alive     returns whether a pid still runs; by default none does
        @returns         the stop result
        """
        return servicectl.stop(fake, services or [self.svc], b.UID, id_prefix="5", clock=self.clock,
                               sleep=self.clock.sleep, alive=alive)


class StopTest(ServiceTest):
    """Tests of `stop`: the repeated bootout, the wait, sudo for system jobs and an interrupt"""

    def test_bootout_repeats_while_it_returns_36(self):
        running = b.printed("gui/501", LABEL, self.plist, self.program, pid=4242)
        fake = self.runner({
            # The refresh, then the check after the bootout that returned 0.
            b.print_key("gui/501", LABEL): [running, b.NOT_FOUND],
            b.bootout_key("gui/501", LABEL): [r.FakeResponse(exit=36), r.FakeResponse(exit=36),
                                              r.FakeResponse(exit=0)],
        })
        result = self.stop(fake)
        self.assertTrue(result.ok)
        self.assertEqual([s.label for s in result.booted], [LABEL])
        self.assertEqual(result.booted[0].domain, "gui/501")
        self.assertEqual(fake.calls.count(b.bootout_key("gui/501", LABEL)), 3)
        self.assertEqual(self.clock.sleeps, [1.0, 1.0])
        self.assertLess(fake.calls.index(b.print_key("gui/501", LABEL)),
                        fake.calls.index(b.bootout_key("gui/501", LABEL)))

    def test_bootout_repeats_while_the_job_is_listed(self):
        running = b.printed("gui/501", LABEL, self.plist, self.program, pid=4242)
        fake = self.runner({b.print_key("gui/501", LABEL): [running, running, running, b.NOT_FOUND],
                            b.bootout_key("gui/501", LABEL): r.FakeResponse(exit=0)})
        result = self.stop(fake)
        self.assertTrue(result.ok)
        self.assertEqual(fake.calls.count(b.bootout_key("gui/501", LABEL)), 3)
        self.assertEqual(self.clock.sleeps, [1.0, 1.0])

    def test_a_job_that_never_exits_outlives_the_wait(self):
        running = b.printed("gui/501", LABEL, self.plist, self.program, pid=4242)
        fake = self.runner({b.print_key("gui/501", LABEL): running,
                            b.bootout_key("gui/501", LABEL): r.FakeResponse(exit=36)})
        result = self.stop(fake)
        self.assertFalse(result.ok)
        self.assertEqual([s.label for s, _ in result.still_running], [LABEL])
        self.assertIn("after 15 s", result.still_running[0][1])
        self.assertEqual(len(self.clock.sleeps), 15)
        self.assertEqual([s.label for s in result.booted], [LABEL])   # restarted by the caller

    def test_a_process_that_outlives_its_job(self):
        running = b.printed("gui/501", LABEL, self.plist, self.program, pid=4242)
        fake = self.runner({b.print_key("gui/501", LABEL): [running, b.NOT_FOUND],
                            b.bootout_key("gui/501", LABEL): r.FakeResponse(exit=0)})
        result = self.stop(fake, alive=lambda pid: pid == 4242)
        self.assertIn("process 4242", result.still_running[0][1])

    def test_pid_alive_reads_kill_zero(self):
        with mock.patch("os.kill", side_effect=ProcessLookupError):
            self.assertFalse(servicectl.pid_alive(4242))
        with mock.patch("os.kill", side_effect=PermissionError):
            self.assertTrue(servicectl.pid_alive(4242))
        with mock.patch("os.kill", return_value=None):
            self.assertTrue(servicectl.pid_alive(4242))
        self.assertFalse(servicectl.pid_alive(None))
        self.assertFalse(servicectl.pid_alive(0))

    def test_system_jobs_need_sudo_others_are_left_alone(self):
        daemon = b.write_plist(self.path("Library", "LaunchDaemons", "org.macports.redis.plist"), "org.macports.redis",
                               "/opt/local/bin/daemondo")
        svc = b.service("org.macports.redis", daemon, "/opt/local", "redis", kind="port", scope="system")
        own = b.service("com.alice.job", "/x.plist", self.prefix, owned=False)
        fake = self.runner({
            b.print_key("system", "org.macports.redis"): [b.printed("system", "org.macports.redis", daemon,
                                                                   "/opt/local/bin/daemondo", pid=99), b.NOT_FOUND],
            b.bootout_key("system", "org.macports.redis", sudo=True): r.FakeResponse(exit=0),
        })
        result = self.stop(fake, [svc, own, self.svc])
        self.assertTrue(result.ok)
        self.assertIn(b.bootout_key("system", "org.macports.redis", sudo=True), fake.calls)
        self.assertEqual([s.label for s in result.refused], ["com.alice.job"])
        self.assertEqual([s.label for s in result.not_loaded], [LABEL])   # launchctl print finds it in no domain

    def test_an_interrupt_is_kept_and_ends_the_stops(self):
        fake = self.runner({b.print_key("gui/501", LABEL): b.printed("gui/501", LABEL, self.plist, self.program)})
        fake.interrupted = True
        result = self.stop(fake)
        self.assertIsInstance(result.error, r.Interrupted)
        self.assertFalse(result.ok)
        self.assertEqual(result.booted, [])


class RestartTest(ServiceTest):
    """Tests of `restart`: `launchctl bootstrap`, `port load` and the cleanup mode"""

    def test_launchctl_bootstrap_in_the_recorded_domain(self):
        fake = self.runner({("/bin/launchctl", "bootstrap", "gui/501", self.plist): r.FakeResponse(exit=0)})
        self.assertEqual(servicectl.restart(fake, [self.svc], id_prefix="5"), [(self.svc, True)])
        self.assertIn(b.print_key("gui/501", LABEL), fake.calls)

    def test_a_startup_item_loads_through_port_when_drivable(self):
        ports = make_instance(Manager.PORTS, "/opt/local")
        item = b.service("org.macports.redis", "/Library/LaunchDaemons/org.macports.redis.plist", "/opt/local",
                         "redis", kind="port", scope="system", domain="system")
        load = (r.SUDO, "-n", "--", "/usr/bin/arch", "-arm64", "/opt/local/bin/port", "-N", "load", "redis")
        fake = self.runner({load: r.FakeResponse(exit=0)})
        self.assertEqual(servicectl.restart(fake, [item], [ports]), [(item, True)])
        ports.drivable = False
        boot = (r.SUDO, "-n", "--", "/bin/launchctl", "bootstrap", "system", item.plist)
        fake = self.runner({boot: r.FakeResponse(exit=5)})
        self.assertEqual(servicectl.restart(fake, [item], [ports]), [(item, False)])
        self.assertIn(boot, fake.calls)

    def test_restart_runs_after_an_interrupt(self):
        fake = self.runner({("/bin/launchctl", "bootstrap", "gui/501", self.plist): r.FakeResponse(exit=0)})
        fake.interrupted = True
        self.assertEqual(servicectl.restart(fake, [self.svc]), [(self.svc, True)])
        self.assertTrue(fake.interrupted)

    def test_a_job_already_loaded_needs_nothing(self):
        fake = self.runner({b.print_key("gui/501", LABEL): b.printed("gui/501", LABEL, self.plist, self.program)})
        self.assertEqual(servicectl.restart(fake, [self.svc]), [(self.svc, True)])
        self.assertFalse([c for c in fake.calls if "bootstrap" in c])


class DeleteTest(ServiceTest):
    """Tests of `delete_plists`: sudo where needed, and a plist that stays"""

    def test_plists_are_deleted_with_sudo_where_needed(self):
        daemon = self.path("Library", "LaunchDaemons", "org.macports.redis.plist")
        os.makedirs(os.path.dirname(daemon))
        with open(daemon, "w") as fh:
            fh.write("x")
        svc = b.service("org.macports.redis", daemon, "/opt/local", "redis", kind="port", scope="system")
        gone = b.service("sh.brew.gone", self.path("nothing.plist"), self.prefix, "gone")
        own = b.service("com.alice.job", self.plist, self.prefix, owned=False)

        def rm(key):
            os.unlink(key[-1])
            return r.FakeResponse()
        fake = self.runner({(r.RM, "-f", self.plist): rm, (r.SUDO, "-n", "--", r.RM, "-f", daemon): rm})
        got = servicectl.delete_plists(fake, [self.svc, svc, gone, own], id_prefix="5")
        self.assertEqual([(s.label, ok) for s, ok in got], [(LABEL, True), ("org.macports.redis", True),
                                                            ("sh.brew.gone", True)])
        self.assertEqual(len(fake.calls), 2)
        self.assertFalse(os.path.lexists(self.plist))

    def test_a_plist_that_stays_is_reported(self):
        fake = self.runner({(r.RM, "-f", self.plist): r.FakeResponse(exit=1, stderr="rm: Permission denied")})
        self.assertEqual(servicectl.delete_plists(fake, [self.svc]), [(self.svc, False)])
        self.assertTrue(system.identity(self.plist))


if __name__ == "__main__":
    unittest.main()

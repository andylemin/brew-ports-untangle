"""`brew-ports rollback` against a made-up Mac: Homebrew and MacPorts instances, and phase 7 services

Also skipped instances, `--dry-run`, `doctor --fix` runs, and the command itself.
"""

import contextlib
import dataclasses
import io
import os
import shutil
import unittest
from unittest import mock

from brew_ports import cli, rollback as rb, runner as r, snapshot, state
from brew_ports.model import Manager, Usability
from tests.unit.fixtures.macports.builders import make_registry, port
from tests.unit.fixtures.rollback import builders as b
from tests.unit.helpers import TempDirTest


class RollbackCase(TempDirTest):
    """The made-up Mac, the `rollback` call and the views of its output that the rollback tests share"""

    def setUp(self):
        super().setUp()
        self.sd = self.state_dir()
        self.sd.ensure()
        self.home = self.path("Users", "alice")
        os.makedirs(os.path.join(self.home, "Library", "LaunchAgents"))
        self.host = b.Host(self.home)
        self.runner = None
        self.ctx = None

    def make_runner(self, ctx, run_dir):
        """Make the rollback's runner over the made-up Mac, and keep it

        @param ctx      the command's context, whose console the runner uses
        @param run_dir  the rollback's own run directory
        @returns        the runner
        """
        self.runner = b.fake(self.host, run_dir, ctx.console)
        return self.runner

    def rollback(self, run_dir, fresh, run_id=None, **kw):
        """Run `rollback` with the discovery passes finding `fresh`, from an empty command log

        @param run_dir  the run to roll back; None with `run_id` for a run that does not exist
        @param fresh    the instances the discovery passes find
        @param run_id   the id the command names; None for the run's own
        @param kw       the context's flags: `yes`, `dry_run`, `tty`
        @returns        the exit status
        """
        self.ctx = b.context(self.sd, self.home, run_id or run_dir.run_id, **kw)
        self.host.commands = []
        brews = [i for i in fresh if i.manager is Manager.BREW]
        ports = [i for i in fresh if i.manager is Manager.PORTS]
        with mock.patch("brew_ports.homebrew.locate.find_instances", return_value=brews), \
                mock.patch("brew_ports.macports.locate.find_instances", return_value=ports):
            return rb.cmd_rollback(self.ctx, make_runner=self.make_runner)

    @property
    def text(self):
        """Return what the rollback printed

        @returns  the console's text
        """
        if self.ctx is None:
            self.fail("no rollback ran")
        return self.ctx.console.text

    def rollback_dir(self):
        """Return the rollback's own run directory

        @returns  the run directory `make_runner` received
        """
        if self.runner is None:
            self.fail("no rollback made its runner")
        return self.runner.run_dir

    def report(self):
        """Return `report.md`; it is redacted, so only path-free lines are compared with it

        @returns  the report's text
        """
        with open(self.rollback_dir().sub("report.md"), encoding="utf-8") as fh:
            return fh.read()

    def brew_commands(self, inst):
        """Return the commands run with an instance's `brew`

        @param inst  the Homebrew instance
        @returns     each command's words after the binary, in order
        """
        return [argv[argv.index(inst.binary) + 1:] for argv in self.host.commands if inst.binary in argv]

    def port_commands(self, inst, verb):
        """Return the commands of a verb run with an instance's `port`

        @param inst  the MacPorts instance
        @param verb  a word the command holds, such as `install`
        @returns     each command's words after the binary and `-N`, in order
        """
        return [argv[argv.index(inst.binary) + 2:] for argv in self.host.commands
                if inst.binary in argv and verb in argv]

    def ports_instance(self, rel="opt/local", **kw):
        """Make a MacPorts instance whose `port` writes to its registry on the made-up Mac

        @param rel  the prefix below the temporary directory, with `/` separators
        @param kw   further fields of the instance
        @returns    the instance
        """
        inst = b.instance(self.tmp, Manager.PORTS, rel, **kw)
        if inst.binary is None or inst.portdbpath is None:
            self.fail("the MacPorts instance has no port or no portdbpath")
        self.host.portdbs[inst.binary] = inst.portdbpath
        return inst


class HomebrewTest(RollbackCase):
    """The rollback of a Homebrew source: its Brewfile or installs, its services, and what stays a gap"""

    def setUp(self):
        super().setUp()
        self.src = b.instance(self.tmp, Manager.BREW, "intel/brew")
        self.target = b.instance(self.tmp, Manager.BREW, "opt/homebrew")

    def postgres(self):
        """Record a loaded `postgresql@16` job of the source, which the made-up Mac starts again

        @returns  the service
        """
        plist = b.write_plist(os.path.join(self.home, "Library", "LaunchAgents", "homebrew.mxcl.postgresql@16.plist"),
                              "homebrew.mxcl.postgresql@16", self.src.prefix + "/opt/postgresql@16/bin/postgres")
        self.host.items["postgresql@16"] = (b.GUI, "homebrew.mxcl.postgresql@16", plist,
                                            self.src.prefix + "/opt/postgresql@16/bin/postgres")
        self.host.load("postgresql@16")
        return b.service(self.src, "homebrew.mxcl.postgresql@16", plist, "postgresql@16", domain=b.GUI)

    def test_brewfile_then_formulae_then_service(self):
        for name, requested, tap in (("wget", True, "homebrew/core"), ("libidn2", False, "homebrew/core"),
                                     ("oldfmt", None, "alice/tools"), ("postgresql@16", True, "homebrew/core"),
                                     ("jq", True, "homebrew/core")):
            b.keg(self.src.prefix, name, requested=requested, tap=tap)
        for token in ("firefox", "zoom", "iterm2"):
            b.room(self.src.prefix, token)
        svc = self.postgres()
        firefox = b.package(self.src, "firefox", kind="cask")
        casks = [firefox, b.package(self.src, "zoom", kind="cask", privileged_install=True),
                 b.package(self.src, "iterm2", kind="cask")]
        self.host.dump = ('tap "homebrew/core"\nbrew "postgresql@16"\nbrew "wget"\ncask "firefox"\ncask "iterm2"\n'
                          'cask "zoom"\n')
        the_plan = b.plan(self.target, [self.target, self.src], mappings=[b.adoption(firefox)],
                          removal_set={self.src.prefix: [("formula", "wget"), ("cask-adopted", "firefox")]})
        run = b.source_run(self.sd, self.host, b.bundle([self.src, self.target], packages=casks, services=[svc]),
                           [self.src, self.target], the_plan=the_plan)
        self.assertTrue(os.path.isfile(os.path.join(snapshot.brew_dir(run, self.src.prefix), snapshot.BREWFILE)))
        for name in ("wget", "libidn2", "oldfmt", "postgresql@16"):
            b.drop(self.src.prefix, "Cellar", name)
        for token in ("firefox", "zoom", "iterm2"):
            b.drop(self.src.prefix, "Caskroom", token)
        b.room(self.target.prefix, "firefox")
        self.host.jobs.clear()

        code = self.rollback(run, [self.src, self.target])

        self.assertEqual(code, rb.EXIT_VERIFY)
        filtered = os.path.join(self.rollback_dir().sub("brewfiles", "brew-" + state.slug(self.src.prefix)), "Brewfile")
        self.assertEqual(self.brew_commands(self.src), [
            ["bundle", "install", "--no-upgrade", "--file=" + filtered],
            ["install", "--formula", "--as-dependency", "libidn2"],
            ["install", "--formula", "alice/tools/oldfmt"],
            ["services", "start", "postgresql@16"]])
        self.assertEqual(self.host.bundles, ['tap "homebrew/core"\nbrew "postgresql@16"\nbrew "wget"\ncask "iterm2"\n'])
        self.assertIn((b.GUI, "homebrew.mxcl.postgresql@16"), self.host.jobs)
        self.assertFalse(os.path.isdir(os.path.join(self.src.prefix, "Caskroom", "firefox")))
        self.assertIn(f"rollback: 1 did not come back:\n  {self.src.prefix}: cask zoom: Homebrew needs sudo for it: "
                      f"run `{self.src.binary} install --cask zoom` on a terminal\n", self.text)
        self.assertIn("cask firefox stays with the instance that adopted it in this run", self.text)
        self.assertIn("the filtered Brewfile omits the casks firefox, zoom", self.text)
        self.assertEqual(self.brew_commands(self.target), [])
        dirty = self.sd.dirty()
        if dirty is None:
            self.fail("the rollback left no dirty marker")
        self.assertEqual(dirty["command"], "rollback")
        self.assertIn("rollback: 1 did not come back:", self.report())

    def test_without_brewfile_taps_casks_and_formulae(self):
        self.src.drivable = False
        self.src.usability = Usability.CANNOT_RUN
        for name, requested, tap in (("wget", True, "homebrew/core"), ("oldfmt", True, "alice/tools"),
                                     ("libidn2", False, "homebrew/core"), ("bat", None, "homebrew/core")):
            b.keg(self.src.prefix, name, requested=requested, tap=tap)
        for token in ("firefox", "iterm2"):
            b.room(self.src.prefix, token)
        firefox = b.package(self.src, "firefox", kind="cask")
        the_plan = b.plan(self.target, [self.target, self.src],
                          removal_set={self.src.prefix: [("cask-adopted", "firefox"), ("cask", "iterm2")]})
        run = b.source_run(self.sd, self.host, b.bundle([self.src, self.target], packages=[firefox]),
                           [self.src, self.target], the_plan=the_plan)
        self.assertFalse(os.path.exists(os.path.join(snapshot.brew_dir(run, self.src.prefix), snapshot.BREWFILE)))
        for name in ("wget", "oldfmt", "libidn2", "bat"):
            b.drop(self.src.prefix, "Cellar", name)
        for token in ("firefox", "iterm2"):
            b.drop(self.src.prefix, "Caskroom", token)
        fresh = dataclasses.replace(self.src, drivable=True, usability=Usability.USABLE)

        code = self.rollback(run, [fresh, self.target])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(self.brew_commands(self.src), [
            ["tap", "alice/tools"],
            ["install", "--cask", "iterm2"],
            ["install", "--formula", "alice/tools/oldfmt"],
            ["install", "--formula", "wget"],
            ["install", "--formula", "bat"],
            ["install", "--formula", "--as-dependency", "libidn2"]])
        self.assertIn("cask firefox stays with the instance that adopted it in this run", self.text)
        self.assertIn("every package, service and selection of the snapshot is back", self.report())

    def test_failed_reinstall_is_a_gap(self):
        self.src.drivable = False
        b.keg(self.src.prefix, "wget")
        b.keg(self.src.prefix, "jq")
        run = b.source_run(self.sd, self.host, b.bundle([self.src]), [self.src])
        b.drop(self.src.prefix, "Cellar", "wget")
        b.drop(self.src.prefix, "Cellar", "jq")
        self.host.fail = {"jq"}

        code = self.rollback(run, [dataclasses.replace(self.src, drivable=True)])

        self.assertEqual(code, rb.EXIT_VERIFY)
        self.assertEqual(self.brew_commands(self.src), [["install", "--formula", "jq"],
                                                        ["install", "--formula", "wget"]])
        self.assertTrue(os.path.isdir(os.path.join(self.src.prefix, "Cellar", "wget")))
        self.assertIn(f"{self.src.prefix}: formula jq: still absent after its reinstall", self.text)
        self.assertNotIn("formula wget:", self.text)

    def test_failed_and_system_services_are_gaps(self):
        self.src.drivable = False
        b.keg(self.src.prefix, "redis")
        b.keg(self.src.prefix, "dnsmasq")
        redis = self.src.prefix + "/opt/redis/bin/redis-server"
        dnsmasq = self.src.prefix + "/opt/dnsmasq/sbin/dnsmasq"
        agent = b.write_plist(os.path.join(self.home, "Library", "LaunchAgents", "homebrew.mxcl.redis.plist"),
                              "homebrew.mxcl.redis", redis)
        daemon = b.write_plist(self.path("Library", "LaunchDaemons", "homebrew.mxcl.dnsmasq.plist"),
                               "homebrew.mxcl.dnsmasq", dnsmasq)
        self.host.jobs[(b.GUI, "homebrew.mxcl.redis")] = (agent, redis)
        self.host.jobs[("system", "homebrew.mxcl.dnsmasq")] = (daemon, dnsmasq)
        services = [b.service(self.src, "homebrew.mxcl.redis", agent, "redis", domain=b.GUI),
                    b.service(self.src, "homebrew.mxcl.dnsmasq", daemon, "dnsmasq", scope="system", domain="system")]
        run = b.source_run(self.sd, self.host, b.bundle([self.src], services=services), [self.src])
        b.drop(self.src.prefix, "Cellar", "redis")
        b.drop(self.src.prefix, "Cellar", "dnsmasq")
        self.host.jobs.clear()

        code = self.rollback(run, [dataclasses.replace(self.src, drivable=True)])

        self.assertEqual(code, rb.EXIT_VERIFY)
        self.assertEqual(self.brew_commands(self.src), [["install", "--formula", "dnsmasq"],
                                                        ["install", "--formula", "redis"],
                                                        ["services", "start", "redis"]])
        self.assertIn(f"by hand: sudo {self.src.binary} services start dnsmasq (homebrew.mxcl.dnsmasq, a system-scope "
                      "service)", self.text)
        self.assertIn(f"{self.src.prefix}: service homebrew.mxcl.redis: `brew services start redis` failed",
                      self.text)
        self.assertIn(f"{self.src.prefix}: service homebrew.mxcl.dnsmasq: a system-scope service: run "
                      f"`sudo {self.src.binary} services start dnsmasq` on a terminal", self.text)

    def test_dry_run_prints_the_commands_and_runs_none(self):
        b.keg(self.src.prefix, "wget")
        self.host.dump = 'brew "wget"\n'
        run = b.source_run(self.sd, self.host, b.bundle([self.src]), [self.src])
        b.drop(self.src.prefix, "Cellar", "wget")

        code = self.rollback(run, [self.src], dry_run=True)

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(self.host.commands, [])
        self.assertIsNone(self.sd.dirty())
        self.assertIn(f"run: /usr/bin/arch -arm64 {self.src.binary} bundle install --no-upgrade --file=", self.text)
        self.assertIn("rollback --dry-run: nothing was run", self.report())
        self.assertFalse(os.path.isdir(os.path.join(self.src.prefix, "Cellar", "wget")))

    def test_a_declined_confirmation_changes_nothing(self):
        b.keg(self.src.prefix, "wget")
        self.host.dump = 'brew "wget"\n'
        run = b.source_run(self.sd, self.host, b.bundle([self.src]), [self.src])
        b.drop(self.src.prefix, "Cellar", "wget")

        code = self.rollback(run, [self.src], yes=False)

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(self.host.ran("bundle", "install"), [])
        self.assertIsNone(self.sd.dirty())
        self.assertIn("rollback: nothing changed", self.text)

    def test_doctor_fix_run_uses_its_own_snapshot(self):
        b.keg(self.src.prefix, "wget")
        self.host.dump = 'brew "wget"\n'
        run = b.source_run(self.sd, self.host, b.bundle([self.src]), [self.src], id_prefix="doctor")
        run.write_json("doctor.json", "{}")
        b.drop(self.src.prefix, "Cellar", "wget")

        code = self.rollback(run, [self.src])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertIn("a doctor --fix run", self.text)
        self.assertEqual(len(self.host.ran("bundle", "install", "--no-upgrade")), 1)
        self.assertTrue(os.path.isdir(os.path.join(self.src.prefix, "Cellar", "wget")))

    def test_no_drivable_instance_exits_3(self):
        b.keg(self.src.prefix, "wget")
        run = b.source_run(self.sd, self.host, b.bundle([self.src]), [self.src])
        b.drop(self.src.prefix, "Cellar", "wget")
        fresh = dataclasses.replace(self.src, drivable=False, usability=Usability.CANNOT_RUN,
                                    usability_detail="Homebrew's portable Ruby is missing")

        code = self.rollback(run, [fresh])

        self.assertEqual(code, rb.EXIT_PREFLIGHT)
        self.assertIn("skipped: it cannot be driven (cannot-run: Homebrew's portable Ruby is missing)", self.text)
        self.assertIn("`brew-ports doctor` names the repair", self.text)
        self.assertIn("not restored: formula wget", self.text)
        self.assertIn("no instance of the snapshot can be driven", self.report())
        self.assertEqual(self.host.ran("install"), [])

    def test_upgrades_and_archives_are_only_listed(self):
        b.keg(self.target.prefix, "openssl@3", "3.4.0", requested=False)
        the_plan = b.plan(self.target, [self.target], target_upgrades=["openssl@3"])
        run = b.source_run(self.sd, self.host, b.bundle([self.target]), [self.target], the_plan=the_plan)
        b.keg(self.target.prefix, "openssl@3", "3.5.1", requested=False)
        archives = {"%opt%local%var%db%redis.tar.gz": "data-archive", "%opt%local%etc.tar.gz": "data-archive",
                    "%opt%homebrew.stash.patch": "data-archive", "%opt%local%bin%stray.tar": "backup/strays"}
        for name, where in archives.items():
            self.write(os.path.join(run.path, where, name), "x")

        code = self.rollback(run, [self.target])

        self.assertEqual(code, rb.EXIT_OK)
        keg = os.path.join(self.target.prefix, "Cellar", "openssl@3", "3.4.0")
        self.assertIn(f"openssl@3: 3.5.1, upgraded from 3.4.0; the old keg stays at {keg}", self.text)
        data = run.sub("data-archive")
        self.assertIn(f"/opt/local/var/db/redis: sudo /usr/bin/tar -xzpf {data}/%opt%local%var%db%redis.tar.gz -C /",
                      self.text)
        self.assertIn("/opt/local/bin/stray: sudo /usr/bin/tar -xpf "
                      f"{run.sub('backup', 'strays')}/%opt%local%bin%stray.tar -C /", self.text)
        self.assertIn(f"/opt/homebrew: /usr/bin/git -C /opt/homebrew apply {data}/%opt%homebrew.stash.patch",
                      self.text)
        self.assertIn("rollback: nothing to run", self.text)
        self.assertEqual(self.host.ran("tar"), [])


class MacPortsTest(RollbackCase):
    """The rollback of a MacPorts source: installs, selections and startup items, gaps and reinstall lines"""

    def redis(self, ports):
        """Record a loaded `redis` startup item of a MacPorts instance, which the made-up Mac loads again

        @param ports  the MacPorts instance
        @returns      the service
        """
        daemon = b.write_plist(self.path("Library", "LaunchDaemons", "org.macports.redis.plist"), "org.macports.redis",
                               ports.prefix + "/bin/daemondo")
        self.host.items["redis"] = ("system", "org.macports.redis", daemon, ports.prefix + "/bin/daemondo")
        self.host.load("redis")
        return b.service(ports, "org.macports.redis", daemon, "redis", scope="system", domain="system")

    def test_install_then_select_then_load(self):
        ports = self.ports_instance(features=("snapshot",))
        brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        make_registry(ports.portdbpath, ports=[
            port(1, "curl", "8.4.0", variants="+ssl", requested_variants="+ssl"),
            port(2, "python312", "3.12.7"),
            port(3, "redis", "7.2.4"),
            port(4, "zlib", "1.2", state="imaged", requested=0),
            port(5, "zlib", "1.3", requested=0)])
        self.host.selected[ports.binary] = {"python3": "python312"}
        svc = self.redis(ports)
        run = b.source_run(self.sd, self.host, b.bundle([ports, brew], services=[svc]), [ports])
        self.assertEqual(snapshot.read_snapshot_id(os.path.join(snapshot.ports_dir(run, ports.prefix),
                                                                snapshot.SNAPSHOT_ID)), 1)
        b.drop_rows(ports.portdbpath, "curl", "redis", "zlib")
        self.host.selected[ports.binary] = {"python3": "none"}
        self.host.jobs.clear()

        code = self.rollback(run, [ports, brew])

        self.assertEqual(code, rb.EXIT_OK)
        tail = [argv[argv.index(ports.binary):] for argv in self.host.commands
                if ports.binary in argv and argv[0] == r.SUDO]
        self.assertEqual(tail, [
            [ports.binary, "-N", "-t", "install", "--no-rev-upgrade", "curl", "+ssl"],
            [ports.binary, "-N", "-t", "install", "--no-rev-upgrade", "redis"],
            [ports.binary, "-N", "-t", "install", "--unrequested", "--no-rev-upgrade", "zlib"],
            [ports.binary, "-N", "select", "--set", "python3", "python312"],
            [ports.binary, "-N", "load", "redis"]])
        self.assertIn(("system", "org.macports.redis"), self.host.jobs)
        self.assertIn("not restorable: zlib @1.2_0 was inactive and its image is gone", self.text)
        self.assertIn(f"by hand instead: sudo {ports.binary} restore --snapshot-id 1 --all (it deactivates every port "
                      "installed since)", self.text)
        self.assertNotIn("did not come back", self.report())

    def python_target(self):
        """Return a run from Homebrew to MacPorts whose phase 7 selected python312 in place of Homebrew's python3

        @returns  the MacPorts target, the Homebrew source and the run
        """
        ports = self.ports_instance()
        brew = b.instance(self.tmp, Manager.BREW, "usr/local")
        make_registry(ports.portdbpath, ports=[port(1, "python312", "3.12.7")])
        self.host.selected[ports.binary] = {"python3": "none"}
        python = b.mapping(b.package(brew, "python@3.12"), "port", "python312", selections=[("python3", "python312")])
        run = b.source_run(self.sd, self.host, b.bundle([ports, brew]), [ports, brew],
                           the_plan=b.plan(ports, [ports, brew], mappings=[python]))
        self.host.selected[ports.binary] = {"python3": "python312"}
        return ports, brew, run

    def test_a_selection_for_a_skipped_source_stays(self):
        ports, brew, run = self.python_target()
        shutil.rmtree(brew.prefix)

        code = self.rollback(run, [ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(self.host.ran("select", "--set"), [])
        self.assertEqual(self.host.selected[ports.binary], {"python3": "python312"})
        self.assertIn(f"port select python3 left as it is: {brew.prefix} (Homebrew) is skipped, so the python3 "
                      "commands phase 7 replaced do not come back", self.text)

    def test_a_selection_goes_back_with_its_source(self):
        ports, brew, run = self.python_target()

        self.assertEqual(self.rollback(run, [ports, brew]), rb.EXIT_OK)
        self.assertEqual(self.host.selected[ports.binary], {"python3": "none"})

    def test_failed_port_is_a_gap_without_trace_mode(self):
        ports = self.ports_instance()
        make_registry(ports.portdbpath, ports=[port(1, "curl", "8.4.0"), port(2, "wget", "1.25")])
        self.host.selected[ports.binary] = {}
        run = b.source_run(self.sd, self.host, b.bundle([ports]), [ports])
        b.drop_rows(ports.portdbpath, "curl", "wget")
        self.host.fail = {"curl"}

        code = self.rollback(run, [ports])

        self.assertEqual(code, rb.EXIT_VERIFY)
        self.assertEqual(self.port_commands(ports, "install"), [["install", "--no-rev-upgrade", "curl"],
                                                                ["install", "--no-rev-upgrade", "wget"]])
        self.assertIn(f"{ports.prefix}: port curl: still absent after `port install`", self.text)
        self.assertNotIn("port wget:", self.text)

    def test_manager_repair_records_are_rolled_back(self):
        ports = self.ports_instance()
        make_registry(ports.portdbpath, ports=[port(1, "curl", "8.4.0"), port(2, "zlib", "1.3", requested=0)])
        run = self.sd.new_run()
        snapshot.write_ports_records(run, ports, [])
        run.write_json("doctor.json", "{}")
        b.deactivate(ports.portdbpath, "zlib")

        code = self.rollback(run, [ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(self.port_commands(ports, "install"), [["install", "--unrequested", "--no-rev-upgrade",
                                                                 "zlib"]])
        self.assertIn("a doctor --fix run", self.text)
        self.assertNotIn("phase 1", self.text)

    def test_target_upgrade_lists_its_activate_line(self):
        ports = self.ports_instance()
        make_registry(ports.portdbpath, ports=[port(1, "curl", "8.4.0")])
        self.host.selected[ports.binary] = {}
        the_plan = b.plan(ports, [ports], target_upgrades=["curl"])
        run = b.source_run(self.sd, self.host, b.bundle([ports]), [ports], the_plan=the_plan)
        b.add_row(ports.portdbpath, "curl", [], version="8.5.0")

        code = self.rollback(run, [ports])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertIn(f"curl: @8.5.0_0, upgraded from @8.4.0_0; sudo {ports.binary} -N activate curl @8.4.0_0 "
                      "brings it back", self.text)
        self.assertEqual(self.port_commands(ports, "activate"), [])

    def test_deleted_manager_gets_reinstall_lines(self):
        ports = self.ports_instance("opt/local2")
        brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        make_registry(ports.portdbpath, ports=[port(1, "curl", "8.4.0"), port(2, "zlib", "1.3", requested=0)])
        self.host.selected[ports.binary] = {}
        the_plan = b.plan(brew, [brew, ports], options={"remove_manager": ports.prefix})
        run = b.source_run(self.sd, self.host, b.bundle([ports, brew]), [ports, brew], the_plan=the_plan)
        etc = self.write(run.sub("data-archive", state.slug(os.path.join(ports.prefix, "etc")) + ".tar.gz"), "x")
        export = self.write(os.path.join(snapshot.ports_dir(run, ports.prefix), snapshot.PORTS_SNAPSHOT), "{}")
        shutil.rmtree(ports.prefix)

        code = self.rollback(run, [brew])

        self.assertEqual(code, rb.EXIT_VERIFY)
        text = self.text
        self.assertIn(f"{ports.prefix} (MacPorts): skipped: no port instance is found at {ports.prefix}", text)
        self.assertIn(f"reinstall MacPorts from source with ./configure --prefix={ports.prefix}", text)
        for name in ("sources.conf", "macports.conf", "variants.conf"):
            self.assertIn(f"then compare {ports.prefix}/etc/macports/{name} with "
                          f"`tar -xzf {etc} -O {ports.prefix.lstrip('/')}/etc/macports/{name}`", text)
        self.assertIn(f"then run `brew-ports rollback {run.run_id}` again", text)
        self.assertIn(f"by hand: sudo {ports.binary} snapshot --import {export}, then sudo {ports.binary} "
                      "restore --last --all", text)
        for name in ("curl", "zlib"):
            self.assertIn(f"{ports.prefix}: port {name}: not restored: the instance is skipped: no port instance "
                          "is found", text)
        self.assertIn("rollback: 2 did not come back:", self.report())

    def test_reinstall_lines_per_prefix(self):
        source = rb.SourceRun(state.RunDir(self.path("run")), None, [], [], [])
        self.assertEqual(rb.reinstall_lines(Manager.BREW, "/usr/local", "arm64", source),
                         ['reinstall the Intel Homebrew: arch -x86_64 /bin/bash -c "$(curl -fsSL '
                          f'{rb.INSTALL_SCRIPT})"'])
        self.assertEqual(rb.reinstall_lines(Manager.BREW, "/opt/homebrew", "arm64", source),
                         [f"reinstall Homebrew from the .pkg of {rb.BREW_RELEASES}"])
        self.assertEqual(rb.reinstall_lines(Manager.BREW, "/usr/local", "x86_64", source),
                         [f"reinstall Homebrew from the .pkg of {rb.BREW_RELEASES}"])
        self.assertEqual(rb.reinstall_lines(Manager.BREW, "/Users/alice/brew", "arm64", source),
                         [f"reinstall Homebrew at /Users/alice/brew: git clone {rb.BREW_REPOSITORY} /Users/alice/brew"])
        self.assertEqual(rb.reinstall_lines(Manager.PORTS, "/opt/local", "arm64", source),
                         ["reinstall MacPorts with `brew-ports bootstrap-ports`"])


class Phase7Test(RollbackCase):
    """The target services phase 7 started: stopped before the source services they replaced start, else left"""

    def redis_source(self):
        """Make a MacPorts source whose loaded `redis` startup item the snapshot records, which the made-up Mac loads

        @returns  the instance, the service, and the plan's mapping of the port to the formula `redis`
        """
        ports = self.ports_instance()
        make_registry(ports.portdbpath, ports=[port(1, "redis", "7.2.4")])
        self.host.selected[ports.binary] = {}
        daemon = b.write_plist(self.path("Library", "LaunchDaemons", "org.macports.redis.plist"), "org.macports.redis",
                               ports.prefix + "/bin/daemondo")
        self.host.items["redis"] = ("system", "org.macports.redis", daemon, ports.prefix + "/bin/daemondo")
        self.host.load("redis")
        svc = b.service(ports, "org.macports.redis", daemon, "redis", scope="system", domain="system")
        return ports, svc, b.mapping(b.package(ports, "redis"), "formula", "redis")

    def started(self, run, brew, label):
        """Load the Homebrew target's `redis` job under a label, and journal the phase 7 start that loaded it

        @param run    the run whose journal gets the start
        @param brew   the Homebrew target
        @param label  the label the job is loaded under
        @returns      the job's plist
        """
        if brew.binary is None:
            self.fail("the Homebrew instance has no brew")
        program = brew.prefix + "/opt/redis/bin/redis-server"
        plist = b.write_plist(os.path.join(self.home, "Library", "LaunchAgents", label + ".plist"), label, program)
        self.host.jobs[(b.GUI, label)] = (plist, program)
        b.journal(run, b.command(7, "7.start.homebrew.mxcl.redis",
                                 [r.ARCH, "-arm64", brew.binary, "services", "start", "redis"]))
        return plist

    def test_target_services_stop_before_sources_start(self):
        ports, svc, redis = self.redis_source()
        brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        the_plan = b.plan(brew, [brew, ports], mappings=[redis], options={"start_services": "true"})
        run = b.source_run(self.sd, self.host, b.bundle([ports, brew], services=[svc]), [ports, brew],
                           the_plan=the_plan)
        b.drop_rows(ports.portdbpath, "redis")
        self.host.jobs.clear()
        label = "homebrew.mxcl.redis"
        plist = self.started(run, brew, label)

        code = self.rollback(run, [ports, brew])

        self.assertEqual(code, rb.EXIT_OK)
        bootout = self.host.commands.index([b.LAUNCHCTL, "bootout", f"{b.GUI}/{label}"])
        install = next(i for i, argv in enumerate(self.host.commands) if "install" in argv and ports.binary in argv)
        load = next(i for i, argv in enumerate(self.host.commands) if "load" in argv and ports.binary in argv)
        self.assertLess(install, bootout)
        self.assertLess(bootout, load)
        self.assertFalse(os.path.exists(plist))
        self.assertNotIn((b.GUI, label), self.host.jobs)
        self.assertIn(("system", "org.macports.redis"), self.host.jobs)
        self.assertIn(f"{label}: boot out the job of redis and delete {plist}", self.text)

    def test_sh_brew_label_is_booted_out_too(self):
        ports, svc, redis = self.redis_source()
        brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        run = b.source_run(self.sd, self.host, b.bundle([ports, brew], services=[svc]), [ports, brew],
                           the_plan=b.plan(brew, [brew, ports], mappings=[redis]))
        self.host.jobs.clear()
        plist = self.started(run, brew, "sh.brew.redis")

        code = self.rollback(run, [ports, brew])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(self.host.ran(b.LAUNCHCTL, "bootout"), [[b.LAUNCHCTL, "bootout", b.GUI + "/sh.brew.redis"]])
        self.assertFalse(os.path.exists(plist))
        self.assertEqual(list(self.host.jobs), [("system", "org.macports.redis")])

    def test_a_start_stays_while_its_source_part_is_skipped(self):
        ports, svc, redis = self.redis_source()
        brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        the_plan = b.plan(brew, [brew, ports], mappings=[redis],
                          options={"start_services": "true", "remove_manager": ports.prefix})
        run = b.source_run(self.sd, self.host, b.bundle([ports, brew], services=[svc]), [ports, brew],
                           the_plan=the_plan)
        shutil.rmtree(ports.prefix)
        self.host.jobs.clear()
        label = "homebrew.mxcl.redis"
        plist = self.started(run, brew, label)

        code = self.rollback(run, [brew])

        self.assertEqual(code, rb.EXIT_VERIFY)
        self.assertEqual(self.host.ran(b.LAUNCHCTL, "bootout"), [])
        self.assertTrue(os.path.exists(plist))
        self.assertIn((b.GUI, label), self.host.jobs)
        self.assertIn(f"target services that phase 7 of the run started, left running:\n  {label}: {ports.prefix} "
                      "(MacPorts) is skipped, so nothing starts org.macports.redis again", self.text)

    def reinstalled_redis(self):
        """Return a run whose rollback reinstalls the source's redis before its startup item starts again

        @returns  the run, the Homebrew target, and the label and plist of the job phase 7 started
        """
        ports, svc, redis = self.redis_source()
        brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        run = b.source_run(self.sd, self.host, b.bundle([ports, brew], services=[svc]), [ports, brew],
                           the_plan=b.plan(brew, [brew, ports], mappings=[redis]))
        b.drop_rows(ports.portdbpath, "redis")
        self.host.jobs.clear()
        label = "homebrew.mxcl.redis"
        return run, ports, brew, label, self.started(run, brew, label)

    def test_an_early_interrupt_leaves_the_target_running(self):
        run, ports, brew, label, plist = self.reinstalled_redis()
        self.host.interrupt = {"redis"}

        with self.assertRaises(r.Interrupted):
            self.rollback(run, [ports, brew])

        self.assertIn((b.GUI, label), self.host.jobs)
        self.assertTrue(os.path.exists(plist))
        self.assertEqual(self.host.ran(b.LAUNCHCTL, "bootout"), [])
        self.assertNotIn("started again", self.text)

    def test_an_interrupt_after_the_boot_out_starts_the_target_again(self):
        run, ports, brew, label, plist = self.reinstalled_redis()
        self.host.interrupt = {label}

        with self.assertRaises(r.Interrupted):
            self.rollback(run, [ports, brew])

        self.assertEqual(len(self.host.ran(b.LAUNCHCTL, "bootout")), 1)
        self.assertIn((b.GUI, label), self.host.jobs)
        self.assertTrue(os.path.exists(plist))
        self.assertIn(f"{label}: started again, as no service it replaced came back", self.text)

    def test_a_target_service_starts_again_when_its_source_does_not(self):
        run, ports, brew, label, plist = self.reinstalled_redis()
        self.host.fail = {"redis"}

        code = self.rollback(run, [ports, brew])

        self.assertEqual(code, rb.EXIT_VERIFY)
        self.assertIn((b.GUI, label), self.host.jobs)
        self.assertTrue(os.path.exists(plist))
        self.assertIn(f"{label}: started again, as no service it replaced came back", self.text)
        self.assertIn(f"{ports.prefix}: service org.macports.redis: its port redis is not active", self.text)

    def postgres_target(self):
        """Return a run from Homebrew to MacPorts whose phase 7 loaded postgresql16-server for Homebrew's postgresql@16

        The Homebrew job is down, as phase 5 left it, and the made-up Mac loads both jobs again.

        @returns  the run, the MacPorts target, the Homebrew source and the Homebrew job's label
        """
        ports = self.ports_instance()
        brew = b.instance(self.tmp, Manager.BREW, "usr/local")
        if ports.binary is None:
            self.fail("the MacPorts instance has no port")
        make_registry(ports.portdbpath, ports=[port(1, "postgresql16-server", "16.10")])
        self.host.selected[ports.binary] = {}
        b.keg(brew.prefix, "postgresql@16")
        label, program = "homebrew.mxcl.postgresql@16", brew.prefix + "/opt/postgresql@16/bin/postgres"
        agent = b.write_plist(os.path.join(self.home, "Library", "LaunchAgents", label + ".plist"), label, program)
        self.host.items["postgresql@16"] = (b.GUI, label, agent, program)
        self.host.load("postgresql@16")
        svc = b.service(brew, label, agent, "postgresql@16", domain=b.GUI)
        server = b.mapping(b.package(brew, "postgresql@16"), "port", "postgresql16-server")
        run = b.source_run(self.sd, self.host, b.bundle([ports, brew], services=[svc]), [ports, brew],
                           the_plan=b.plan(ports, [ports, brew], mappings=[server]))
        self.host.jobs.clear()
        self.host.items["postgresql16-server"] = ("system", "org.macports.postgresql16-server",
                                                  "/Library/LaunchDaemons/x.plist", "x")
        self.host.load("postgresql16-server")
        b.journal(run, b.command(7, "7.start.org.macports.postgresql16-server",
                                 [r.ARCH, "-arm64", ports.binary, "-N", "load", "postgresql16-server"], sudo=True))
        return run, ports, brew, label

    def test_a_macports_item_phase_7_loaded_is_unloaded(self):
        run, ports, brew, label = self.postgres_target()

        code = self.rollback(run, [ports, brew])

        self.assertEqual(code, rb.EXIT_OK)
        self.assertEqual(self.port_commands(ports, "unload"), [["unload", "postgresql16-server"]])
        self.assertNotIn(("system", "org.macports.postgresql16-server"), self.host.jobs)
        self.assertIn((b.GUI, label), self.host.jobs)
        unload = next(i for i, argv in enumerate(self.host.commands) if "unload" in argv)
        start = self.host.commands.index(self.host.ran("services", "start", "postgresql@16")[0])
        self.assertLess(unload, start)

    def test_a_macports_item_loads_again_without_its_source(self):
        run, ports, brew, label = self.postgres_target()
        self.host.fail = {"postgresql@16"}

        code = self.rollback(run, [ports, brew])

        self.assertEqual(code, rb.EXIT_VERIFY)
        self.assertEqual(self.port_commands(ports, "load"), [["load", "postgresql16-server"]])
        self.assertIn(("system", "org.macports.postgresql16-server"), self.host.jobs)
        self.assertNotIn((b.GUI, label), self.host.jobs)
        self.assertIn("org.macports.postgresql16-server: started again, as no service it replaced came back", self.text)
        self.assertIn(f"{brew.prefix}: service {label}: `brew services start postgresql@16` failed", self.text)


class CommandTest(RollbackCase):
    """The `rollback` command: the real parser, unknown and unreadable runs, and what it reads from a journal"""

    def test_cli_main_runs_it_with_the_real_parser(self):
        brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        b.keg(brew.prefix, "wget")
        self.host.dump = 'brew "wget"\n'
        run = b.source_run(self.sd, self.host, b.bundle([brew]), [brew])
        b.drop(brew.prefix, "Cellar", "wget")
        seen = []

        def handler(ctx):
            seen.append((ctx.args.run_id, ctx.yes, ctx.args.dry_run))
            return rb.cmd_rollback(ctx, make_runner=self.make_runner)

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(cli.COMMANDS, {"rollback": handler}), \
                mock.patch("brew_ports.system.running_as_root", return_value=False), \
                mock.patch("brew_ports.homebrew.locate.find_instances", return_value=[brew]), \
                mock.patch("brew_ports.macports.locate.find_instances", return_value=[]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--state-dir", self.sd.path, "rollback", run.run_id, "--yes"],
                            environ={"HOME": self.home, "USER": b.USER})

        self.assertEqual(code, rb.EXIT_OK, err.getvalue())
        self.assertEqual(seen, [(run.run_id, True, False)])
        self.assertTrue(os.path.isdir(os.path.join(brew.prefix, "Cellar", "wget")))

    def test_an_unknown_run_is_a_usage_error(self):
        self.assertEqual(self.rollback(None, [], run_id="20990101-000000-abcdef"), rb.EXIT_USAGE)
        self.assertIn("no run 20990101-000000-abcdef", self.text)

    def test_run_without_snapshot_is_refused(self):
        empty = self.sd.new_run()
        self.assertEqual(self.rollback(empty, []), rb.EXIT_PREFLIGHT)
        self.assertIn("holds no snapshot", self.text)

    def test_an_unreadable_plan_is_a_preflight_failure(self):
        brew = b.instance(self.tmp, Manager.BREW, "opt/homebrew")
        run = b.source_run(self.sd, self.host, b.bundle([brew]), [brew])
        run.write_json("plan.json", "{not json")
        self.assertEqual(self.rollback(run, [brew]), rb.EXIT_PREFLIGHT)
        self.assertIn("plan.json cannot be read", self.text)

    def journaled_source(self):
        """Return a source run whose journal holds phase 7 starts and a phase 5 shell switch

        @returns  the run, as `load_source` reads it
        """
        run = self.sd.new_run()
        brew = "/opt/homebrew/bin/brew"
        b.journal(run,
                  b.command(7, "7.start.sh.brew.redis", [r.ARCH, "-arm64", brew, "services", "start", "redis"]),
                  b.command(7, "7.start.sh.brew.failed", [brew, "services", "start", "failed"], exit_code=1),
                  b.command(7, "7.start.org.macports.redis", ["/opt/local/bin/port", "-N", "load", "redis"], sudo=True),
                  b.command(5, "5.shell", [rb.CHSH, "-s", "/opt/homebrew/bin/bash", "alice"], sudo=True),
                  {"phase": 5, "action_id": "5.shell", "result": "ok", "from": "/opt/local/bin/bash"})
        return rb.load_source(self.sd, run.run_id)

    def test_phase7_starts_that_exited_0(self):
        starts = rb.phase7_starts(self.journaled_source().entries)
        self.assertEqual([(s.label, s.manager, s.name) for s in starts],
                         [("sh.brew.redis", Manager.BREW, "redis"), ("org.macports.redis", Manager.PORTS, "redis")])

    def test_shell_switch_from_the_journal(self):
        self.assertEqual(rb.shell_switch(self.journaled_source(), self.sd),
                         rb.ShellSwitch("alice", "/opt/homebrew/bin/bash", "/opt/local/bin/bash"))


if __name__ == "__main__":
    unittest.main()

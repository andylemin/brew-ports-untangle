"""`brew-ports doctor` end to end against FakeRunner: the report, `doctor.json`, the exit codes and `--fix`"""

import functools
import json
import os
import shutil
import sys
import unittest
from unittest import mock

from brew_ports import doctor, model, runner as r, servicectl, snapshot, system
from brew_ports.model import Manager, Severity
from tests.unit.fixtures.doctor import builders as b
from tests.unit.helpers import TempDirTest, make_instance, make_package

LABEL = "sh.brew.mysql"


class Responder:
    """The host's answers: launchctl, brew bundle and info, tmutil and rm by rule, the rest from `exact`

    An `exact` value is a response, a list of responses, or a callable.
    """

    def __init__(self, test):
        """Answer for one test, with no exact answer yet

        @param test  the test, whose state directory and run the answers read
        """
        self.test = test
        self.exact = {}
        self.prints = {}          # label -> list of responses for `launchctl print`
        self.bootout = r.FakeResponse(exit=0)
        self.marker_seen = {}     # command word -> whether the dirty marker existed when it ran

    def note_marker(self, word):
        """Record whether the dirty marker existed when a command first ran

        @param word  the command's name in `marker_seen`
        """
        self.marker_seen.setdefault(word, os.path.exists(self.test.sd.dirty_path))

    def __call__(self, key):
        """Answer one command

        @param key  the command's argv
        @returns    the response
        """
        if key in self.exact:
            resp = self.exact[key]
            if isinstance(resp, list):
                resp = resp.pop(0)
            return resp(key) if callable(resp) else resp
        tail = [k for k in key if k not in (r.SUDO, "-n", "--")]
        if tail[:2] == ["/bin/launchctl", "print"]:
            label = tail[2].split("/")[-1]
            queue = self.prints.get(label) or []
            return queue.pop(0) if queue else b.NOT_FOUND
        if tail[:2] == ["/bin/launchctl", "bootout"]:
            self.note_marker("bootout")
            return self.bootout
        if tail[:2] == ["/bin/launchctl", "bootstrap"]:
            return r.FakeResponse()
        if tail[:2] == [r.RM, "-f"]:
            os.unlink(tail[2])
            return r.FakeResponse()
        if "bundle" in key and "dump" in key:
            path = next(a for a in key if a.startswith("--file="))[len("--file="):]
            path = path.replace("<run>", self.test.run_path())
            with open(path, "w") as fh:
                fh.write('brew "mysql"\n')
            return r.FakeResponse()
        if "info" in key and "--installed" in key:
            return r.FakeResponse(stdout="{}")
        if key[0] == snapshot.TMUTIL:
            self.note_marker("tmutil")
        return r.FakeResponse()


def binary_of(inst: model.Instance) -> str:
    """Return the manager binary of a test instance, which is always made with one

    @param inst  the instance
    @returns     the binary's path
    """
    if inst.binary is None:
        raise AssertionError(f"the instance at {inst.prefix} has no manager binary")
    return inst.binary


class FixTest(TempDirTest):
    """`brew-ports doctor` against a fake host: one Homebrew instance, a responder and the runners it made"""

    def setUp(self):
        super().setUp()
        self.sd = self.state_dir()
        self.ctx = b.context(self.sd)              # replaced by the context of each doctor()
        prefix = self.path("opt", "homebrew")
        os.makedirs(os.path.join(prefix, "bin"))
        self.brew = make_instance(Manager.BREW, prefix, identity=system.identity(prefix), owned_roots=(prefix,))
        self.responder = Responder(self)
        self.runners = []
        self.clock = b.FakeClock()
        for patcher in (mock.patch("brew_ports.system.free_bytes", return_value=100 * doctor.GIB),
                        mock.patch("brew_ports.servicectl.stop", functools.partial(
                            servicectl.stop, clock=self.clock, sleep=self.clock.sleep, alive=lambda pid: False))):
            patcher.start()
            self.addCleanup(patcher.stop)

    @property
    def fake(self):
        """Return the runner of the last `doctor()`

        @returns  the runner
        """
        return self.runners[-1]

    def run_path(self):
        """Return the run directory of the command that is running

        @returns  the directory's path
        """
        return self.runners[-1].run_dir.path

    def factory(self, sudo_ok=True):
        """Return a `make_runner` whose FakeRunner the responder answers, kept in `runners`

        @param sudo_ok  whether the sudo probes and the preflight succeed
        @returns        the factory
        """
        def make(ctx, run_dir):
            fake = r.FakeRunner(default=self.responder, console=ctx.console, environ=dict(ctx.environ),
                                run_dir=run_dir, sudo_ok=sudo_ok)
            self.runners.append(fake)
            return fake
        return make

    def doctor(self, bundle, mods, answers=(), tty=False, sudo_ok=True, **kw):
        """Run `brew-ports doctor` over a bundle with the given health modules

        @param bundle   the scan `scan.obtain` hands back
        @param mods     the `sys.modules` entries of the health modules
        @param answers  the terminal answers, in order
        @param tty      whether the prompts can be answered
        @param sudo_ok  whether the sudo probes and the preflight succeed
        @param kw       the command's argument values, such as `fix=True`
        @returns        the exit code
        """
        ctx = b.context(self.sd, answers, tty=tty, **kw)
        with mock.patch("brew_ports.scan.obtain", return_value=(bundle, False)), mock.patch.dict(sys.modules, mods):
            code = doctor.cmd_doctor(ctx, make_runner=self.factory(sudo_ok))
        self.ctx = ctx
        return code

    def output(self):
        """Return what the last command printed

        @returns  the console's text
        """
        return self.ctx.console.text

    def brew_action(self, step, *args, sudo=False, on_failure=model.OnFailure.STOP):
        """Return a remedy that runs the Homebrew instance's brew

        @param step        the action id after `doctor.`
        @param args        the brew arguments
        @param sudo        whether it runs under sudo
        @param on_failure  its failure policy
        @returns           the action
        """
        return model.Action(action_id=f"doctor.{step}", kind="command", argv=[binary_of(self.brew)] + list(args),
                            sudo=sudo, description=" ".join(args), env_profile="brew",
                            instance_prefix=self.brew.prefix, on_failure=on_failure)

    def issue(self, code, subject, *actions, severity=Severity.HIGH, **flags):
        """Return a finding about the Homebrew instance

        @param code      the finding's name
        @param subject   its subject, or None
        @param actions   its remedies
        @param severity  its severity, HIGH unless given
        @param flags     the `_issue` flags, such as `confirm_each=True`
        @returns         the finding
        """
        return doctor._issue(code, severity, f"{code} title", subject, self.brew.prefix,
                             evidence=[f"evidence of {code}"], remedies=list(actions), **flags)

    def bundle(self, services=()):
        """Return a scan of the Homebrew instance alone

        @param services  its services
        @returns         the bundle
        """
        return b.bundle(instances=[self.brew], services=list(services))

    def key(self, action):
        """Return the FakeRunner key an action runs under

        @param action  a command action
        @returns       its argv, after `sudo -n --` when it escalates
        """
        return ((r.SUDO, "-n", "--") if action.sudo else ()) + tuple(action.argv)

    def ran(self, action):
        """Return whether the last command ran an action

        @param action  a command action
        @returns       True when its key is among the runner's calls
        """
        return self.key(action) in self.fake.calls


class ReportTest(FixTest):
    """The report, `doctor.json` and the exit codes, without `--fix`"""

    def test_report_doctor_json_and_exit_codes(self):
        versions = self.issue("brew-several-versions", "wget", severity=Severity.LOW)
        bundle = self.bundle()
        bundle.notes.append("/opt/local: no PortIndex (no synced ports tree)")
        skipped = "/opt/local: port diagnose skipped: MacPorts there is platform-mismatch"
        code = self.doctor(bundle, b.health_modules(brew=[versions], ports_notes=[skipped]))
        self.assertEqual(code, doctor.EXIT_FINDINGS)
        with open(os.path.join(self.fake.run_dir.path, "doctor.json"), encoding="utf-8") as fh:
            text = fh.read()
        result = model.from_json(model.DoctorResult, text)
        self.assertEqual([i.code for i in result.issues], ["brew-several-versions"])
        self.assertEqual(set(result.blocks_apply), {"brew", "ports"})
        self.assertEqual(json.loads(text)["notes"], ["/opt/local: no PortIndex (no synced ports tree)", skipped])
        self.assertIn("LOW\n  brew-several-versions  brew-several-versions title: wget", self.output())
        self.assertIn("blocks apply (target brew): none", self.output())
        self.assertIn("note: " + skipped, self.output())
        self.assertFalse(os.path.exists(self.sd.dirty_path))

    def test_info_only_exits_zero_and_json_prints_the_result(self):
        several = self.issue("brew-several-prefixes", None, severity=Severity.INFO)
        code = self.doctor(self.bundle(), b.health_modules(brew=[several]), json=True)
        self.assertEqual(code, doctor.EXIT_OK)
        data = json.loads(self.ctx.console.stream.getvalue())
        self.assertEqual([i["code"] for i in data["issues"]], ["brew-several-prefixes"])
        self.assertEqual(data["notes"], [])


class FixFlowTest(FixTest):
    """`--fix` over an auto-fix remedy, a confirmed one and a removal that needs an answer on a terminal"""

    def setUp(self):
        super().setUp()
        self.dependency = self.issue("brew-missing-dependency", "jq",
                                     self.brew_action("brew-missing-dependency.jq.install", "install", "--formula",
                                                      "oniguruma"),
                                     auto_fix=True, repairs_install=True)
        self.unlinked = self.issue("brew-unlinked-keg", "wget",
                                   self.brew_action("brew-unlinked-keg.wget.link", "link", "wget"), confirm_each=True)
        self.versions = self.issue("brew-several-versions", "curl",
                                   self.brew_action("brew-several-versions.curl.rm", "rm", "1.0"), confirm_each=True,
                                   severity=Severity.LOW)
        self.mods = lambda **kw: b.health_modules(brew=[self.dependency, self.unlinked, self.versions],
                                                  brew_terminal=["brew-several-versions"], **kw)

    def test_yes_applies_all_but_terminal_removals(self):
        code = self.doctor(self.bundle(), self.mods(), fix=True, yes=True)
        self.assertTrue(self.ran(self.dependency.remedies[0]))
        self.assertTrue(self.ran(self.unlinked.remedies[0]))
        self.assertFalse(self.ran(self.versions.remedies[0]))
        self.assertIn("brew-several-versions needs an answer on a terminal: not applied", self.output())
        self.assertEqual(code, doctor.EXIT_FINDINGS)            # the several versions are left
        self.assertLess(self.fake.calls.index(self.key(self.dependency.remedies[0])),
                        self.fake.calls.index(self.key(self.unlinked.remedies[0])))
        results = [e for e in self.fake.run_dir.journal.entries() if "result" in e]
        self.assertEqual([(e["action_id"], e["result"]) for e in results],
                         [("doctor.brew-missing-dependency.jq.install", "ok"),
                          ("doctor.brew-unlinked-keg.wget.link", "ok")])

    def test_per_item_answers_on_a_terminal(self):
        code = self.doctor(self.bundle(), self.mods(), answers=[True, False, True], tty=True, fix=True)
        self.assertEqual(len(self.ctx.asked), 3)
        self.assertTrue(self.ctx.asked[0].startswith("Apply these 1 remedies"))
        self.assertTrue(self.ran(self.dependency.remedies[0]))
        self.assertFalse(self.ran(self.unlinked.remedies[0]))
        self.assertTrue(self.ran(self.versions.remedies[0]))
        self.assertEqual(code, doctor.EXIT_FINDINGS)            # the answer declines the unlinked keg

    def test_no_answer_applies_nothing(self):
        self.doctor(self.bundle(), self.mods(), fix=True)
        self.assertFalse(any(self.ran(i.remedies[0]) for i in (self.dependency, self.unlinked, self.versions)))
        self.assertFalse(os.path.exists(self.sd.dirty_path))

    def test_dry_run_prints_every_remedy_and_runs_nothing(self):
        code = self.doctor(self.bundle(), self.mods(), fix=True, dry_run=True, yes=True)
        self.assertEqual(code, doctor.EXIT_FINDINGS)
        self.assertEqual(self.fake.calls, [])
        out = self.output()
        self.assertIn("nothing is run", out)
        for issue in (self.dependency, self.unlinked, self.versions):
            self.assertIn(doctor.describe(issue.remedies[0]), out)
        self.assertFalse(os.path.exists(self.sd.dirty_path))
        self.assertFalse(self.fake.sudo_ready)

    def test_marker_is_touched_before_the_first_change(self):
        seen: list[bool] = []

        def install(_key):
            seen.append(os.path.exists(self.sd.dirty_path))
            return r.FakeResponse()
        self.responder.exact[self.key(self.dependency.remedies[0])] = install
        self.doctor(self.bundle(), self.mods(), fix=True, yes=True)
        self.assertEqual(seen, [True])
        marker = self.sd.dirty()
        if marker is None:
            self.fail("the fix left no dirty marker")
        self.assertEqual((marker["run_id"], marker["command"]), (self.fake.run_dir.run_id, "doctor --fix"))

    def test_a_failed_action_stops_with_exit_4(self):
        self.responder.exact[self.key(self.dependency.remedies[0])] = r.FakeResponse(exit=1,
                                                                                     stderr="Error: no bottle")
        code = self.doctor(self.bundle(), self.mods(), fix=True, yes=True)
        self.assertEqual(code, doctor.EXIT_ACTION)
        self.assertFalse(self.ran(self.unlinked.remedies[0]))
        self.assertIn("doctor --fix stopped", self.output())

    def test_a_failed_post_check_stops_with_exit_4(self):
        code = self.doctor(self.bundle(), self.mods(brew_verified={"brew-missing-dependency": False}), fix=True,
                           yes=True)
        self.assertEqual(code, doctor.EXIT_ACTION)
        self.assertIn("post-check of brew-missing-dependency", self.output())
        results = [e for e in self.fake.run_dir.journal.entries() if "result" in e]
        self.assertEqual([(e["action_id"], e["result"]) for e in results],
                         [("doctor.brew-missing-dependency.jq.install", "failed")])

    def test_env_override_refuses_brew_remedies(self):
        override = self.issue("brew-env-override", "/etc/homebrew/brew.env:1")
        mods = b.health_modules(brew=[override, self.dependency, self.unlinked])
        self.doctor(self.bundle(), mods, fix=True, yes=True)
        self.assertFalse(self.ran(self.dependency.remedies[0]))
        self.assertFalse(self.ran(self.unlinked.remedies[0]))
        self.assertIn(f"brew-env-override holds for {self.brew.prefix}", self.output())


class SudoTest(FixTest):
    """The sudo preflight of escalated remedies, and a manager repair"""

    def setUp(self):
        super().setUp()
        self.ports = make_instance(Manager.PORTS, self.path("opt", "local"))
        action = model.Action(action_id="doctor.ports-missing-file.curl.deactivate", kind="command",
                              argv=[binary_of(self.ports), "-N", "-f", "deactivate", "curl", "@8.4.0_0"], sudo=True,
                              description="deactivate", env_profile="ports", instance_prefix=self.ports.prefix)
        self.missing = doctor._issue("ports-missing-file", Severity.HIGH, "Active file missing", "curl",
                                     self.ports.prefix, remedies=[action], confirm_each=True)

    def test_an_escalated_remedy_runs_the_preflight_first(self):
        bundle = b.bundle(instances=[self.brew, self.ports])
        self.assertEqual(self.doctor(bundle, b.health_modules(ports=[self.missing]), fix=True, yes=True,
                                     sudo_ok=False), doctor.EXIT_PREFLIGHT)
        self.assertFalse(self.ran(self.missing.remedies[0]))
        self.doctor(b.bundle(instances=[self.brew, self.ports]), b.health_modules(ports=[self.missing]), fix=True,
                    yes=True)
        self.assertTrue(self.fake.sudo_ready)
        self.assertTrue(self.ran(self.missing.remedies[0]))

    def test_no_escalated_remedy_no_preflight(self):
        unlinked = self.issue("brew-unlinked-keg", "wget", self.brew_action("brew-unlinked-keg.wget.link", "link",
                                                                            "wget"), confirm_each=True)
        self.doctor(self.bundle(), b.health_modules(brew=[unlinked]), fix=True, yes=True, sudo_ok=False)
        self.assertFalse(self.fake.sudo_ready)
        self.assertTrue(self.ran(unlinked.remedies[0]))

    def test_manager_repair_skips_the_rest_of_its_instance(self):
        code = "ports-registry-schema-update"
        version = model.Action(action_id=f"doctor.{code}.version", kind="command",
                               argv=[binary_of(self.ports), "-N", "version"], sudo=True, description="version",
                               env_profile="ports", instance_prefix=self.ports.prefix)
        schema = doctor._issue(code, Severity.HIGH, "Registry awaiting its schema update", self.ports.prefix,
                               self.ports.prefix, remedies=[version], confirm_each=True)
        mods = b.health_modules(ports=[self.missing, schema], ports_repairs=[code])
        exit_code = self.doctor(b.bundle(instances=[self.brew, self.ports]), mods, fix=True, yes=True)
        repairs = mods["brew_ports.macports.health"].calls
        self.assertEqual(repairs, [(code, self.fake.run_dir.run_id)])
        self.assertFalse(self.ran(self.missing.remedies[0]))
        self.assertFalse(self.ran(schema.remedies[0]))           # manager_repair runs it, not doctor
        self.assertIn(f"repaired {code}", self.output())
        self.assertIn("run `brew-ports doctor --rescan`", self.output())
        self.assertTrue(os.path.exists(self.sd.dirty_path))
        self.assertEqual(exit_code, doctor.EXIT_FINDINGS)

    def test_a_manager_repair_skips_rebuilds_of_its_ports(self):
        code = "ports-registry-schema-update"
        version = model.Action(action_id=f"doctor.{code}.version", kind="command",
                               argv=[binary_of(self.ports), "-N", "version"], sudo=True, description="version",
                               env_profile="ports", instance_prefix=self.ports.prefix)
        schema = doctor._issue(code, Severity.HIGH, "Registry awaiting its schema update", self.ports.prefix,
                               self.ports.prefix, remedies=[version], confirm_each=True)
        rebuild = port_action(self.ports, "doctor.env-cross-prefix-linkage.curl.rebuild", "-n", "upgrade", "--force",
                              "--no-replace", "--no-rev-upgrade", "curl")
        cross = doctor._issue("env-cross-prefix-linkage", Severity.HIGH, "Cross-prefix linkage", "curl",
                              self.ports.prefix, remedies=[rebuild], confirm_each=True)
        mods = b.health_modules(ports=[cross, schema], ports_repairs=[code])
        self.doctor(b.bundle(instances=[self.brew, self.ports]), mods, fix=True, yes=True)
        self.assertFalse(self.ran(rebuild))
        self.assertIn(f"env-cross-prefix-linkage curl: skipped, the manager repair changed {self.ports.prefix}; "
                      "run `brew-ports doctor --rescan`", self.output())


class RemovalTest(FixTest):
    """A removal behind a terminal answer: the snapshot, the service stop, the uninstall, then the plist"""

    def setUp(self):
        super().setUp()
        self.rack = os.path.join(self.brew.prefix, "Cellar", "mysql", "9.0")
        os.makedirs(self.rack)
        self.datadir = os.path.join(self.brew.prefix, "var", "mysql")
        os.makedirs(self.datadir)
        self.program = os.path.join(self.brew.prefix, "opt", "mysql", "bin", "mysqld_safe")
        self.plist = b.write_plist(self.path("Users", "alice", "Library", "LaunchAgents", LABEL + ".plist"), LABEL,
                                   self.program)
        self.svc = b.service(LABEL, self.plist, self.brew.prefix, "mysql", domain="gui/501", loaded=True, pid=4242,
                             data_dirs=[self.datadir])
        code = "brew-deleted-formula"
        self.uninstall = self.brew_action(code + ".mysql.uninstall", "uninstall", "--formula", "--force", "mysql")
        deleted = self.issue(code, "mysql", self.uninstall, confirm_each=True, severity=Severity.MEDIUM)
        self.mods = b.health_modules(brew=[deleted], brew_terminal=[code], brew_removes={code: ("formula", "mysql")})
        running = b.printed("gui/501", LABEL, self.plist, self.program, pid=4242)
        # The snapshot's refresh, the stop's refresh, then gone after the bootout.
        self.responder.prints[LABEL] = [running, running, b.NOT_FOUND]

    def remove_rack(self, _key):
        """Answer the uninstall as brew does: the mysql rack goes

        @param _key  the uninstall's argv
        @returns     a success
        """
        shutil.rmtree(os.path.dirname(self.rack))
        return r.FakeResponse()

    def index(self, predicate):
        """Return the position of the first command the predicate accepts

        @param predicate  takes an argv
        @returns          the index into the runner's calls
        """
        return next(i for i, call in enumerate(self.fake.calls) if predicate(call))

    def test_snapshot_stop_remove_then_delete_plist(self):
        self.responder.exact[self.key(self.uninstall)] = self.remove_rack
        code = self.doctor(self.bundle([self.svc]), self.mods, answers=[True], tty=True, fix=True)
        self.assertEqual(code, doctor.EXIT_OK)
        self.assertIn(f"data directories of mysql: {self.datadir}", self.output())
        dump = self.index(lambda c: "dump" in c)
        bootout = self.index(lambda c: c[:2] == ("/bin/launchctl", "bootout"))
        removal = self.fake.calls.index(self.key(self.uninstall))
        rm = self.fake.calls.index((r.RM, "-f", self.plist))
        self.assertLess(dump, bootout)
        self.assertLess(bootout, removal)
        self.assertLess(removal, rm)
        self.assertFalse(os.path.exists(self.plist))
        d = snapshot.brew_dir(self.fake.run_dir, self.brew.prefix)
        with open(os.path.join(d, snapshot.FORMULAE)) as fh:
            self.assertIn("mysql\tnone\t-\t9.0", fh.read())
        self.assertTrue(snapshot.is_complete(self.fake.run_dir))
        self.assertEqual(self.responder.marker_seen, {"tmutil": True, "bootout": True})

    def test_yes_never_answers_the_removal(self):
        self.doctor(self.bundle([self.svc]), self.mods, fix=True, yes=True)
        self.assertFalse(self.ran(self.uninstall))
        self.assertFalse([c for c in self.fake.calls if "bootout" in c])
        self.assertTrue(os.path.exists(self.plist))

    def test_stuck_job_exits_4_before_any_removal(self):
        running = b.printed("gui/501", LABEL, self.plist, self.program, pid=4242)
        self.responder.prints[LABEL] = [running] * 40
        self.responder.bootout = r.FakeResponse(exit=36)
        code = self.doctor(self.bundle([self.svc]), self.mods, answers=[True], tty=True, fix=True)
        self.assertEqual(code, doctor.EXIT_ACTION)
        self.assertFalse(self.ran(self.uninstall))
        self.assertTrue(os.path.exists(self.plist))
        self.assertIn(f"the service {LABEL} did not stop within", self.output())
        self.assertEqual(len(self.clock.sleeps), 30)                 # exit_timeout_s 20 + 10

    def test_a_package_that_stays_gets_its_service_back(self):
        code = self.doctor(self.bundle([self.svc]), self.mods, answers=[True], tty=True, fix=True)
        self.assertEqual(code, doctor.EXIT_OK)
        self.assertIn(("/bin/launchctl", "bootstrap", "gui/501", self.plist), self.fake.calls)
        self.assertTrue(os.path.exists(self.plist))


def port_action(inst, action_id, *args):
    """Return an escalated remedy that runs `port -N` of a MacPorts instance

    @param inst       the instance
    @param action_id  the action's id
    @param args       the port arguments
    @returns          the action
    """
    return model.Action(action_id=action_id, kind="command", argv=[inst.binary, "-N"] + list(args), sudo=True,
                        description=" ".join(args), env_profile="ports", instance_prefix=inst.prefix)


LEAF = "ports-unrequested-leaf"


class LeafTest(FixTest):
    """Unrequested leaves are recomputed from a fresh registry backup after each removal"""

    def setUp(self):
        super().setUp()
        self.ports = make_instance(Manager.PORTS, self.path("opt", "local"))

    def leaf(self, name):
        """Return the unrequested-leaf finding of a port, whose remedy uninstalls it

        @param name  the port
        @returns     the finding
        """
        return doctor._issue(LEAF, Severity.INFO, "Unrequested leaf", name, self.ports.prefix, confirm_each=True,
                             remedies=[port_action(self.ports, f"doctor.{LEAF}.{name}.uninstall", "uninstall",
                                                   name, "@1.0_0")])

    def fix(self, answers, rounds):
        """Run `--fix` on a terminal over the leaves a and b

        @param answers  the terminal answers, in order
        @param rounds   the leaves each recomputation returns, in order
        @returns        the fake MacPorts health module
        """
        mods = b.health_modules(ports=[self.leaf("a"), self.leaf("b")], ports_terminal=[LEAF],
                                ports_removes={LEAF: "port"}, ports_leaves=lambda prefix: rounds.pop(0))
        self.doctor(b.bundle(instances=[self.brew, self.ports]), mods, answers=answers, tty=True, fix=True)
        return mods["brew_ports.macports.health"]

    def removed(self):
        """Return the ports the fix uninstalled

        @returns  their names, in order
        """
        return [c[-2] for c in self.fake.calls if "uninstall" in c]

    def test_leaves_are_recomputed_after_a_removal(self):
        ports = self.fix([True, True], [[self.leaf("c")], []])
        self.assertEqual(self.removed(), ["a", "c"])                 # b is no leaf once a is gone
        self.assertEqual(self.ctx.asked, [f"Apply {LEAF} to a?", f"Apply {LEAF} to c?"])
        self.assertEqual(ports.recomputed, [self.ports.prefix, self.ports.prefix])

    def test_a_declined_leaf_is_not_offered_again(self):
        self.fix([False, True, True], [[self.leaf("a"), self.leaf("c")], []])
        self.assertEqual(self.ctx.asked, [f"Apply {LEAF} to {name}?" for name in "abc"])
        self.assertEqual(self.removed(), ["b", "c"])


class PortServiceTest(FixTest):
    """A removal stops services only when it touches the active row or the whole port"""

    def setUp(self):
        super().setUp()
        prefix = self.path("opt", "local")
        self.ports = make_instance(Manager.PORTS, prefix)
        daemondo = prefix + "/bin/daemondo"
        self.daemon = b.write_plist(self.path("Library", "LaunchDaemons", "org.macports.redis.plist"),
                                    "org.macports.redis", daemondo)
        self.svc = b.service("org.macports.redis", self.daemon, prefix, "redis", kind="port", scope="system",
                             domain="system", loaded=True, pid=99)
        self.rows = [make_package("redis", kind="port", prefix=prefix, spec_args=["redis", "@7.2_0"]),
                     make_package("redis", kind="port", prefix=prefix, spec_args=["redis", "@7.0_0"], active=False)]
        running = b.printed("system", "org.macports.redis", self.daemon, daemondo, pid=99)
        # The snapshot's refresh, the stop's refresh, then gone after the bootout.
        self.responder.prints["org.macports.redis"] = [running, running, b.NOT_FOUND]

    def fix(self, issue):
        """Run `--fix` on a terminal over one redis finding, answering yes

        @param issue  the finding
        @returns      the exit code
        """
        mods = b.health_modules(ports=[issue], ports_terminal=["ports-inactive-versions"],
                                ports_removes={"ports-inactive-versions": "port", "ports-missing-image": "port"})
        bundle = b.bundle(instances=[self.brew, self.ports], packages=self.rows, services=[self.svc])
        return self.doctor(bundle, mods, answers=[True], tty=True, fix=True)

    def bootouts(self):
        """Return the `launchctl bootout` commands the fix ran

        @returns  their argvs, in order
        """
        return [c for c in self.fake.calls if "bootout" in c]

    def test_inactive_row_removal_keeps_the_service(self):
        inactive = doctor._issue("ports-inactive-versions", Severity.LOW, "Inactive versions", "redis",
                                 self.ports.prefix, confirm_each=True,
                                 remedies=[port_action(self.ports, "doctor.ports-inactive-versions.redis.uninstall",
                                                       "uninstall", "redis", "@7.0_0")])
        self.assertEqual(self.fix(inactive), doctor.EXIT_OK)
        self.assertTrue(self.ran(inactive.remedies[0]))
        self.assertEqual(self.bootouts(), [])
        self.assertNotIn("stop org.macports.redis", self.output())

    def test_rebuild_stops_and_reloads_the_service(self):
        image = doctor._issue("ports-missing-image", Severity.HIGH, "Image missing", "redis", self.ports.prefix,
                              confirm_each=True,
                              remedies=[port_action(self.ports, "doctor.ports-missing-image.redis.rebuild", "-n",
                                                    "upgrade", "--force", "--no-replace", "--no-rev-upgrade",
                                                    "redis")])
        self.assertEqual(self.fix(image), doctor.EXIT_OK)
        self.assertEqual(self.bootouts(), [b.bootout_key("system", "org.macports.redis", sudo=True)])
        load = (r.SUDO, "-n", "--", "/usr/bin/arch", "-arm64", self.ports.binary, "-N", "load", "redis")
        self.assertGreater(self.fake.calls.index(load), self.fake.calls.index(self.key(image.remedies[0])))


def plain_action(action_id, *argv, sudo=False):
    """Return a remedy that runs a plain command, such as `rm`, under no manager's profile

    @param action_id  the action's id
    @param argv       the command
    @param sudo       whether it runs under sudo
    @returns          the action
    """
    return model.Action(action_id=action_id, kind="command", argv=list(argv), sudo=sudo, description=" ".join(argv))


class QueueTest(FixTest):
    """A remedy queued behind one that ran its package's manager on the same package is skipped; others still run"""

    def setUp(self):
        super().setUp()
        prefix = self.path("opt", "local")
        self.ports = make_instance(Manager.PORTS, prefix)
        self.rows = [make_package("curl", kind="port", prefix=prefix, spec_args=["curl", "@8.9.1_0"])]
        self.rows += [make_package("curl", kind="port", prefix=prefix, spec_args=["curl", version], active=False)
                      for version in ("@8.7.0_0", "@8.6.0_0")]

    def skipped(self, code, subject, by, name):
        """Return the line `--fix` prints for a finding it skips because an earlier remedy changed its package

        @param code     the skipped finding's name
        @param subject  its subject
        @param by       the name of the finding whose remedy changed the package
        @param name     the package
        @returns        the line, without its indent
        """
        return f"{code} {subject}: skipped, the {by} remedy changed {name}; run `brew-ports doctor --rescan`"

    def test_a_reactivation_skips_the_plist_removal_queued_behind_it(self):
        code = "ports-missing-file"
        steps = [port_action(self.ports, f"doctor.{code}.curl.{step}", *args)
                 for step, args in (("deactivate", ("-f", "deactivate", "curl", "@8.9.1_0")),
                                    ("activate", ("-f", "activate", "curl", "@8.9.1_0")), ("load", ("load", "curl")))]
        missing = doctor._issue(code, Severity.HIGH, "Active file missing", "curl", self.ports.prefix,
                                remedies=steps, confirm_each=True)
        plist = self.path("Library", "LaunchDaemons", "org.macports.curl.plist")
        svc = b.service("org.macports.curl", plist, self.ports.prefix, "curl", kind="port", scope="system",
                        domain="system", loaded=True)
        drop = [plain_action("doctor.ports-dangling-plist.curl.bootout", "/bin/launchctl", "bootout",
                             "system/org.macports.curl", sudo=True),
                plain_action("doctor.ports-dangling-plist.curl.rm", r.RM, plist, sudo=True)]
        dangling = doctor._issue("ports-dangling-plist", Severity.LOW, "Dangling plist", "org.macports.curl",
                                 self.ports.prefix, remedies=drop, confirm_each=True)
        bundle = b.bundle(instances=[self.brew, self.ports], packages=self.rows, services=[svc])
        exit_code = self.doctor(bundle, b.health_modules(ports=[dangling, missing]), fix=True, yes=True)
        self.assertTrue(all(self.ran(action) for action in steps))
        self.assertFalse(any(self.ran(action) for action in drop))
        self.assertIn(self.skipped("ports-dangling-plist", "org.macports.curl", code, "curl"), self.output())
        self.assertEqual(exit_code, doctor.EXIT_FINDINGS)

    def test_an_auto_install_skips_the_queued_plist_removal(self):
        install = self.brew_action("brew-missing-dependency.jq.install", "install", "--formula", "--as-dependency",
                                   "jq")
        dependency = self.issue("brew-missing-dependency", "jq", install, auto_fix=True)
        plist = self.path("Users", "alice", "Library", "LaunchAgents", "homebrew.mxcl.jq.plist")
        svc = b.service("homebrew.mxcl.jq", plist, self.brew.prefix, "jq")
        rm = plain_action("doctor.brew-orphan-service.jq.rm", r.RM, plist)
        orphan = self.issue("brew-orphan-service", "homebrew.mxcl.jq", rm, confirm_each=True, severity=Severity.LOW)
        self.doctor(self.bundle([svc]), b.health_modules(brew=[orphan, dependency]), fix=True, yes=True)
        self.assertTrue(self.ran(install))
        self.assertFalse(self.ran(rm))
        self.assertIn(self.skipped("brew-orphan-service", "homebrew.mxcl.jq", "brew-missing-dependency", "jq"),
                      self.output())

    def test_removals_of_other_kegs_and_rows_still_run(self):
        kegs = [os.path.join(self.brew.prefix, "Cellar", "wget", version) for version in ("1.0", "2.0")]
        removals = [self.issue("brew-several-versions", keg,
                               plain_action(f"doctor.brew-several-versions.{os.path.basename(keg)}.rm", r.RM, "-rf",
                                            keg), confirm_each=True, severity=Severity.LOW) for keg in kegs]
        rows = [doctor._issue("ports-inactive-versions", Severity.LOW, "Inactive versions", "curl", self.ports.prefix,
                              confirm_each=True,
                              remedies=[port_action(self.ports, f"doctor.ports-inactive-versions.curl.uninstall{v}",
                                                    "uninstall", "curl", v)]) for v in ("@8.7.0_0", "@8.6.0_0")]
        mods = b.health_modules(brew=removals, ports=rows, brew_terminal=["brew-several-versions"],
                                ports_terminal=["ports-inactive-versions"],
                                ports_removes={"ports-inactive-versions": "port"})
        bundle = b.bundle(instances=[self.brew, self.ports], packages=self.rows)
        self.assertEqual(self.doctor(bundle, mods, answers=[True] * 4, tty=True, fix=True), doctor.EXIT_OK)
        self.assertEqual(len(self.ctx.asked), 4)
        self.assertTrue(all(self.ran(issue.remedies[0]) for issue in removals + rows))


class ManagerRepairTest(FixTest):
    """A repair at /opt/local that runs the base package procedure shows its steps in the one prompt"""

    def setUp(self):
        super().setUp()
        self.ports = make_instance(Manager.PORTS, "/opt/local", drivable=False,
                                   usability=model.Usability.MISSING_BINARY)
        cannot = "ports-cannot-run"
        self.cannot_run = doctor._issue(cannot, Severity.HIGH, "port missing while the registry holds ports",
                                        self.ports.prefix, self.ports.prefix, confirm_each=True,
                                        remedies=[doctor.note(cannot, self.ports.prefix, "the base package procedure")])
        self.inner: list[bool] = []

        def repair(_issue, _runner, _run_dir, _environ, _console, *, confirm):
            """Ask the base package procedure's question once and record the answer in `inner`

            @param _issue    the finding
            @param _runner   the runner
            @param _run_dir  the run directory
            @param _environ  the environment
            @param _console  the console
            @param confirm   asks the user a question and returns the answer
            @returns         the report lines
            """
            self.inner.append(confirm("The MacPorts base package procedure:\n  read ...\nRun it?"))
            return ["MacPorts base installed"]
        repairs = ("ports-platform-mismatch", "ports-built-for-other-os", "ports-registry-schema-update", cannot)
        self.mods = b.health_modules(ports=[self.cannot_run], ports_repairs=repairs, ports_repair=repair)

    def test_one_prompt_shows_and_answers_the_procedure(self):
        code = self.doctor(b.bundle(instances=[self.brew, self.ports]), self.mods, answers=[True], tty=True, fix=True)
        self.assertEqual(self.ctx.asked, ["Apply ports-cannot-run to /opt/local?"])
        self.assertEqual(self.inner, [True])
        self.assertIn("MacPorts-<version>-15-<name>.pkg", self.output())
        self.assertIn("MacPorts base installed", self.output())
        self.assertEqual(code, doctor.EXIT_OK)

    def test_dry_run_prints_the_procedure_and_runs_nothing(self):
        self.doctor(b.bundle(instances=[self.brew, self.ports]), self.mods, fix=True, dry_run=True, yes=True)
        self.assertIn("sudo installer -pkg", self.output())
        self.assertEqual(self.mods["brew_ports.macports.health"].calls, [])
        self.assertEqual(self.fake.calls, [])
        self.assertFalse(os.path.exists(self.sd.dirty_path))


OTOOL = """{binary}:
Load command 0
          cmd LC_LOAD_DYLIB
      cmdsize 56
         name {lib} (offset 24)
"""


class CrossLinkageRebuildTest(FixTest):
    """The cross-prefix linkage remedy: `brew reinstall`, then a rescan of the keg decides"""

    def setUp(self):
        super().setUp()
        ports = self.path("opt", "local")
        os.makedirs(os.path.join(ports, "lib"))
        self.libz = os.path.join(ports, "lib", "libz.1.dylib")
        with open(self.libz, "wb") as fh:
            fh.write(b"\xcf\xfa\xed\xfe" + b"\0" * 28)
        self.ports = make_instance(Manager.PORTS, ports, identity=system.identity(ports), owned_roots=(ports,))
        keg = os.path.join(self.brew.prefix, "Cellar", "vim", "9.1")
        os.makedirs(os.path.join(keg, "bin"))
        self.vim = os.path.join(keg, "bin", "vim")
        with open(self.vim, "wb") as fh:
            fh.write(b"\xcf\xfa\xed\xfe" + b"\0" * 28)
        os.makedirs(os.path.join(self.brew.prefix, "opt"))
        os.symlink(keg, os.path.join(self.brew.prefix, "opt", "vim"))
        ref = {"name": self.libz, "command": "LC_LOAD_DYLIB", "resolved": self.libz, "class": "other"}
        self.linkage = {"binaries": {self.vim: {"package": f"{self.brew.prefix}|formula|vim",
                                                "instance_prefix": self.brew.prefix, "archs": [],
                                                "references": [ref], "error": None}}}

    def run_fix(self, lib):
        """Run `--fix --yes` with otool answering that vim's rebuilt binary loads `lib`

        @param lib  the library the rescan finds
        @returns    the exit code
        """
        self.responder.exact[("/usr/bin/otool", "-l", self.vim)] = r.FakeResponse(
            stdout=OTOOL.format(binary=self.vim, lib=lib))
        bundle = b.bundle(instances=[self.brew, self.ports], linkage=self.linkage)
        return self.doctor(bundle, b.health_modules(), fix=True, yes=True)

    def test_a_clean_rescan_passes(self):
        self.assertEqual(self.run_fix("/usr/lib/libSystem.B.dylib"), doctor.EXIT_OK)
        reinstall = [c for c in self.fake.calls if "reinstall" in c]
        self.assertEqual(reinstall[0][-3:], ("reinstall", "--formula", "vim"))
        self.assertTrue(os.path.isfile(os.path.join(snapshot.brew_dir(self.fake.run_dir, self.brew.prefix),
                                                    snapshot.FORMULAE)))

    def test_a_reference_left_into_the_other_prefix_fails(self):
        self.assertEqual(self.run_fix(self.libz), doctor.EXIT_ACTION)
        self.assertIn("post-check of env-cross-prefix-linkage", self.output())


if __name__ == "__main__":
    unittest.main()

"""`brew-ports doctor` end to end against FakeRunner: the report, `doctor.json`, the exit codes and `--fix`"""

import functools
import json
import os
import shutil
import sys
import unittest
from unittest import mock

from brew_ports import (doctor, doctor_report, doctor_target, duplicates, model, runner as r, servicectl, snapshot,
                        system)
from brew_ports.model import Blocks, Manager, Severity
from brew_ports.report import offered, tilde
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
        self.assertEqual(code, doctor.EXIT_OK)                 # it stops no move and nothing is broken
        with open(os.path.join(self.fake.run_dir.path, "doctor.json"), encoding="utf-8") as fh:
            text = fh.read()
        result = model.from_json(model.DoctorResult, text)
        self.assertEqual([i.code for i in result.issues], ["brew-several-versions"])
        self.assertEqual(set(result.blocks_apply), {"brew", "ports"})
        self.assertEqual(json.loads(text)["notes"], ["/opt/local: no PortIndex (no synced ports tree)", skipped])
        # A Mac with one installation gets no heading or suffix that names it.
        self.assertIn("\n\nNothing stops a move. 1 thing is worth cleaning up.\n\n"
                      "Worth cleaning up (1)\n  brew-several-versions title\n", self.output())
        # Only what a check of doctor's own could not run is listed; what the scan noted is for --verbose.
        self.assertIn("\nChecks that could not run\n  " + skipped, self.output())
        self.assertNotIn("no PortIndex", self.output())
        self.assertNotIn("Exit status", self.output())
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
        brew = binary_of(self.brew)
        # It says what it offers first; each command prints once, with its result; the last lines say what it did.
        self.assertEqual(self.output().splitlines()[1:], [
            "doctor --fix offers 3 fixes. --yes answers for you, except where a fix uninstalls a package or one of "
            "its versions, or deletes a cask's record or a stray file: that takes your own answer on a terminal. "
            "`brew-ports doctor` lists everything that was found.",
            "", "brew-missing-dependency title", f"  {brew} install --formula oniguruma ... ok",
            "", "brew-unlinked-keg title", f"  {brew} link wget ... ok",
            "", "brew-several-versions title",
            "  Not asked: this is one of the fixes that take your own answer on a terminal.",
            "", "Made 2 fixes.", "Next: brew-ports doctor   (it checks again and lists what is left)"])
        self.assertEqual(code, doctor.EXIT_OK)                  # what is left stops no move and is not broken
        self.assertLess(self.fake.calls.index(self.key(self.dependency.remedies[0])),
                        self.fake.calls.index(self.key(self.unlinked.remedies[0])))
        results = [e for e in self.fake.run_dir.journal.entries() if "result" in e]
        self.assertEqual([(e["action_id"], e["result"]) for e in results],
                         [("doctor.brew-missing-dependency.jq.install", "ok"),
                          ("doctor.brew-unlinked-keg.wget.link", "ok")])

    def test_per_item_answers_on_a_terminal(self):
        code = self.doctor(self.bundle(), self.mods(), answers=[True, False, True], tty=True, fix=True)
        self.assertEqual(self.ctx.asked, ["Make this fix?"] * 3)
        self.assertTrue(self.ran(self.dependency.remedies[0]))
        self.assertFalse(self.ran(self.unlinked.remedies[0]))
        self.assertTrue(self.ran(self.versions.remedies[0]))
        brew = binary_of(self.brew)
        # Above each question: what a yes runs and what a no does.
        self.assertIn(f"\nbrew-unlinked-keg title\n  y runs `{brew} link wget`; n changes nothing.\n", self.output())
        self.assertIn("\nMade 2 fixes.\nNext: brew-ports doctor   (it checks again and lists what is left)\n"
                      "Exit status 1: something needs a fix before a move, or is broken.\n", self.output())
        self.assertEqual(code, doctor.EXIT_FINDINGS)            # the answer declines the unlinked keg

    def test_several_fixes_of_the_same_kind_take_one_answer(self):
        other = self.issue("brew-missing-dependency", "yq",
                           self.brew_action("brew-missing-dependency.yq.install", "install", "--formula", "libyaml"),
                           auto_fix=True)
        mods = b.health_modules(brew=[self.dependency, other])
        code = self.doctor(self.bundle(), mods, answers=[True], tty=True, fix=True)
        self.assertEqual(self.ctx.asked, ["Make these 2 fixes?"])
        brew = binary_of(self.brew)
        self.assertEqual(self.output().splitlines()[2:], [
            "", "These 2 fixes take one answer:",
            "  brew-missing-dependency title", f"      runs `{brew} install --formula oniguruma`",
            "  brew-missing-dependency title", f"      runs `{brew} install --formula libyaml`",
            "  y makes them; n changes nothing.",
            f"  {brew} install --formula oniguruma ... ok", f"  {brew} install --formula libyaml ... ok",
            "", "Made 2 fixes.", "Next: brew-ports doctor   (it checks again and lists what is left)"])
        self.assertEqual(code, doctor.EXIT_OK)
        # Under --yes nothing is asked, so each command is printed once, with its result, under its finding.
        self.doctor(self.bundle(), mods, fix=True, yes=True)
        self.assertEqual(self.output().splitlines()[2:7], [
            "", "brew-missing-dependency title", f"  {brew} install --formula oniguruma ... ok",
            "brew-missing-dependency title", f"  {brew} install --formula libyaml ... ok"])

    def test_no_answer_applies_nothing(self):
        self.doctor(self.bundle(), self.mods(), fix=True)
        self.assertFalse(any(self.ran(i.remedies[0]) for i in (self.dependency, self.unlinked, self.versions)))
        self.assertFalse(os.path.exists(self.sd.dirty_path))
        # Why no fix is made is said once, in the opening, and no password is asked for.
        self.assertEqual(self.output().splitlines()[1], "doctor --fix offers 3 fixes. There is no terminal to ask on, "
                         "so it makes none of them: `brew-ports doctor --fix --yes` answers for you. `brew-ports "
                         "doctor` lists everything that was found.")
        self.assertNotIn("Not asked", self.output())
        self.assertFalse(self.fake.sudo_ready)
        self.assertIn("\nMade no fix.\nNext: brew-ports doctor   (it lists what was found)\n", self.output())

    def test_dry_run_prints_every_remedy_and_runs_nothing(self):
        code = self.doctor(self.bundle(), self.mods(), fix=True, dry_run=True, yes=True)
        self.assertEqual(code, doctor.EXIT_FINDINGS)
        self.assertEqual(self.fake.calls, [])
        lines = self.output().splitlines()
        self.assertEqual((lines[1], lines[-2:]), ("Dry run: nothing changes.", [
            "Dry run: nothing changed.", "Exit status 1: something needs a fix before a move, or is broken."]))
        # --yes answers for the first two; the removal still waits for an answer on a terminal.
        for issue in (self.dependency, self.unlinked):
            self.assertIn(f"  doctor --fix runs `{doctor.describe(issue.remedies[0])}`.", lines)
        self.assertIn(f"  doctor --fix asks, then runs `{doctor.describe(self.versions.remedies[0])}`.", lines)
        self.assertFalse(os.path.exists(self.sd.dirty_path))
        self.assertFalse(self.fake.sudo_ready)

    def test_a_dry_run_lists_what_shares_an_answer_together(self):
        other = self.issue("brew-missing-dependency", "yq",
                           self.brew_action("brew-missing-dependency.yq.install", "install", "--formula", "libyaml"),
                           auto_fix=True)
        mods = b.health_modules(brew=[self.dependency, other, self.unlinked])
        self.doctor(self.bundle(), mods, fix=True, dry_run=True)
        brew = binary_of(self.brew)
        self.assertEqual(self.output().splitlines()[1:], [
            "Dry run: nothing changes.",
            "doctor --fix offers 3 fixes. It asks before it changes anything. `brew-ports doctor` lists everything "
            "that was found.",
            "", "These 2 fixes take one answer:",
            "  brew-missing-dependency title", f"      runs `{brew} install --formula oniguruma`",
            "  brew-missing-dependency title", f"      runs `{brew} install --formula libyaml`",
            "", "brew-unlinked-keg title", f"  doctor --fix asks, then runs `{brew} link wget`.",
            "", "Dry run: nothing changed.", "Exit status 1: something needs a fix before a move, or is broken."])

    def test_a_dry_run_with_nothing_to_fix_explains_its_status(self):
        broken = self.issue("brew-broken-linkage", "jq")
        code = self.doctor(self.bundle(), b.health_modules(brew=[broken]), fix=True, dry_run=True)
        self.assertEqual(self.output().splitlines()[1:], [
            "Dry run: nothing changes.",
            "No finding has a fix that `doctor --fix` can make. `brew-ports doctor` lists what was found and what to "
            "do about it.",
            "Exit status 1: something needs a fix before a move, or is broken."])
        self.assertEqual(code, doctor.EXIT_FINDINGS)

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
        # The error names the command as it is typed and Homebrew's own error line, then says what to do.
        self.assertEqual(self.ctx.console.err.getvalue().splitlines(), [
            f"brew-ports: `{binary_of(self.brew)} install --formula oniguruma` failed (exit 1): Error: no bottle",
            f"  Its whole output is in the folder `out` of the run folder, {tilde(self.run_path())}.",
            "  Fix the cause, then run `brew-ports doctor --fix` again."])

    def test_a_failed_post_check_stops_with_exit_4(self):
        code = self.doctor(self.bundle(), self.mods(brew_verified={"brew-missing-dependency": False}), fix=True,
                           yes=True)
        self.assertEqual(code, doctor.EXIT_ACTION)
        self.assertIn("brew-ports: the commands ran, but a check afterwards still finds the problem: "
                      "brew-missing-dependency title\n", self.output())
        results = [e for e in self.fake.run_dir.journal.entries() if "result" in e]
        self.assertEqual([(e["action_id"], e["result"]) for e in results],
                         [("doctor.brew-missing-dependency.jq.install", "failed")])

    def test_env_override_refuses_brew_remedies(self):
        override = self.issue("brew-env-override", "/etc/homebrew/brew.env:1")
        mods = b.health_modules(brew=[override, self.dependency, self.unlinked])
        self.doctor(self.bundle(), mods, fix=True, yes=True)
        self.assertFalse(self.ran(self.dependency.remedies[0]))
        self.assertFalse(self.ran(self.unlinked.remedies[0]))
        self.assertEqual(self.output().splitlines()[1:], [
            "No finding has a fix that `doctor --fix` can make. `brew-ports doctor` lists what was found and what to "
            "do about it.",
            "", "Not offered, because a brew.env file changes the settings that brew-ports runs `brew` with "
            "(`brew-ports doctor` lists the lines to remove):",
            "  brew-missing-dependency title", "  brew-unlinked-keg title",
            "Exit status 1: something needs a fix before a move, or is broken."])

    def test_under_json_the_fix_lines_stay_out_of_the_output(self):
        ctx = b.context(self.sd, fix=True, yes=True, json=True)
        ctx.console.json_mode = True                # as the command line sets it for --json
        with mock.patch("brew_ports.scan.obtain", return_value=(self.bundle(), False)), \
                mock.patch.dict(sys.modules, self.mods()):
            doctor.cmd_doctor(ctx, make_runner=self.factory())
        self.assertEqual(len(json.loads(ctx.console.stream.getvalue())["issues"]), 3)
        self.assertIn("\nMade 2 fixes.\n", ctx.console.err.getvalue())


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
        self.assertEqual(self.doctor(bundle, b.health_modules(ports=[self.missing]), fix=True, target="ports",
                                     yes=True, sudo_ok=False), doctor.EXIT_PREFLIGHT)
        self.assertFalse(self.ran(self.missing.remedies[0]))
        self.doctor(b.bundle(instances=[self.brew, self.ports]), b.health_modules(ports=[self.missing]), fix=True,
                    target="ports", yes=True)
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
        exit_code = self.doctor(b.bundle(instances=[self.brew, self.ports]), mods, fix=True, target="ports", yes=True)
        repairs = mods["brew_ports.macports.health"].calls
        self.assertEqual(repairs, [(code, self.fake.run_dir.run_id)])
        self.assertFalse(self.ran(self.missing.remedies[0]))
        self.assertFalse(self.ran(schema.remedies[0]))           # manager_repair runs it, not doctor
        self.assertEqual(self.output().count(f"repaired {code}"), 1)
        at_ports = f"MacPorts at {self.ports.prefix}"
        self.assertIn(f"\nSkipped: Active file missing ({at_ports})\n  An earlier fix of this run changed {at_ports}, "
                      "so this finding may be out of date. `brew-ports doctor --target ports` checks again.\n",
                      self.output())
        self.assertIn("Some of them need your password (sudo).\n", self.output())
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
        self.doctor(b.bundle(instances=[self.brew, self.ports]), mods, fix=True, target="ports", yes=True)
        self.assertFalse(self.ran(rebuild))
        self.assertIn(f"\nSkipped: Cross-prefix linkage (MacPorts at {self.ports.prefix})\n", self.output())


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
        brew, at_brew = binary_of(self.brew), f"Homebrew at {self.brew.prefix}"
        run_dir = self.fake.run_dir
        # What a yes does comes above the question, a step per line; then each step with its result.
        self.assertEqual(self.output().splitlines()[2:], [
            "", "brew-deleted-formula title",
            f"  y saves what is installed in {at_brew}, for `brew-ports rollback`,",
            f"    then stops the service {LABEL},",
            f"    then runs `{brew} uninstall --formula --force mysql`.",
            "  n changes nothing.",
            "  Afterwards it starts that service again; when the package is gone, it deletes its service file "
            "instead.",
            f"  The data of mysql is in {self.datadir}.",
            f"  Saved what is installed in {at_brew} in the run folder, {tilde(run_dir.path)}, for `brew-ports "
            "rollback`.",
            "  macOS also took a local snapshot of the disk, which it keeps for about a day or until it needs the "
            "space.",
            f"  Stopped the service {LABEL}.",
            f"  {brew} uninstall --formula --force mysql ... ok",
            f"  Deleted the service file {tilde(self.plist)}.",
            "", "Made 1 fix.",
            f"If a fix of this run uninstalled something you want back: brew-ports rollback {run_dir.run_id}",
            "Next: brew-ports doctor   (it checks again and lists what is left)"])
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
        return doctor._issue(LEAF, Severity.INFO, f"{name} is a leftover", name, self.ports.prefix, confirm_each=True,
                             remedies=[port_action(self.ports, f"doctor.{LEAF}.{name}.uninstall", "uninstall",
                                                   name, "@1.0_0")])

    def asked_about(self):
        """Return the ports whose fix the run put a question about, read from what it printed above each question

        @returns  their names, in order
        """
        self.assertEqual(self.ctx.asked, ["Make this fix?"] * len(self.ctx.asked))
        return [line.split()[0] for line in self.output().splitlines() if " is a leftover (" in line]

    def fix(self, answers, rounds):
        """Run `--fix` on a terminal over the leaves a and b

        @param answers  the terminal answers, in order
        @param rounds   the leaves each recomputation returns, in order
        @returns        the fake MacPorts health module
        """
        mods = b.health_modules(ports=[self.leaf("a"), self.leaf("b")], ports_terminal=[LEAF],
                                ports_removes={LEAF: "port"}, ports_leaves=lambda prefix: rounds.pop(0))
        self.doctor(b.bundle(instances=[self.brew, self.ports]), mods, answers=answers, tty=True, fix=True,
                    target="ports")
        return mods["brew_ports.macports.health"]

    def removed(self):
        """Return the ports the fix uninstalled

        @returns  their names, in order
        """
        return [c[-2] for c in self.fake.calls if "uninstall" in c]

    def test_leaves_are_recomputed_after_a_removal(self):
        ports = self.fix([True, True], [[self.leaf("c")], []])
        self.assertEqual(self.removed(), ["a", "c"])                 # b is no leaf once a is gone
        self.assertEqual(self.asked_about(), ["a", "c"])
        self.assertEqual(ports.recomputed, [self.ports.prefix, self.ports.prefix])

    def test_a_declined_leaf_is_not_offered_again(self):
        self.fix([False, True, True], [[self.leaf("a"), self.leaf("c")], []])
        self.assertEqual(self.asked_about(), ["a", "b", "c"])
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
        return self.doctor(bundle, mods, answers=[True], tty=True, fix=True, target="ports")

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
        self.assertNotIn("the service org.macports.redis", self.output())

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

    @staticmethod
    def skipped(finding, name, chosen=""):
        """Return the lines `--fix` prints for a finding it skips because an earlier fix changed its package

        @param finding  the skipped finding, as the output names it
        @param name     the package
        @param chosen   the options that name the installation that stays, on a Mac with several
        @returns        the two lines
        """
        return (f"\nSkipped: {finding}\n  An earlier fix of this run changed {name}, so this finding may be out of "
                f"date. `brew-ports doctor{chosen}` checks again.\n")

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
        exit_code = self.doctor(bundle, b.health_modules(ports=[dangling, missing]), fix=True, target="ports",
                                yes=True)
        self.assertTrue(all(self.ran(action) for action in steps))
        self.assertFalse(any(self.ran(action) for action in drop))
        self.assertIn(self.skipped(f"Dangling plist (MacPorts at {self.ports.prefix})", "curl", " --target ports"),
                      self.output())
        self.assertEqual(exit_code, doctor.EXIT_OK)             # what was skipped stops no move and is not broken

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
        self.assertIn(self.skipped("brew-orphan-service title", "jq"), self.output())

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
        for target, mine, others in (("brew", removals, rows), ("ports", rows, removals)):
            bundle = b.bundle(instances=[self.brew, self.ports], packages=self.rows)
            code = self.doctor(bundle, mods, answers=[True] * 4, tty=True, fix=True, target=target)
            self.assertEqual(code, doctor.EXIT_OK)
            self.assertEqual(len(self.ctx.asked), 2)            # the two of the installation that stays
            self.assertTrue(all(self.ran(issue.remedies[0]) for issue in mine))
            self.assertFalse(any(self.ran(issue.remedies[0]) for issue in others))


class ManagerRepairTest(FixTest):
    """A repair at /opt/local that runs the MacPorts installer: one question, which says what a yes does"""

    INSTALLS = "installs MacPorts over /opt/local again from its official signed installer"
    NEEDS = ("It downloads the installer from MacPorts' releases, checks its signature and runs it with your password "
             "(sudo). The installer adds MacPorts to the PATH in your shell's login files. Your installed ports stay.")
    TITLE = "The `port` command of MacPorts at /opt/local is missing or does not start"

    def setUp(self):
        super().setUp()
        self.ports = make_instance(Manager.PORTS, "/opt/local", drivable=False,
                                   usability=model.Usability.MISSING_BINARY)
        cannot = "ports-cannot-run"
        # As the detector builds it: the two notes, then the sync that the repair runs after the installer.
        sync = model.Action(action_id="doctor.ports-cannot-run.sync", kind="command",
                            argv=["/opt/local/bin/port", "-N", "sync"], sudo=True, description="sync",
                            env_profile="ports", instance_prefix=self.ports.prefix)
        self.cannot_run = doctor._issue(cannot, Severity.HIGH, self.TITLE, self.ports.prefix, self.ports.prefix,
                                        confirm_each=True,
                                        remedies=[doctor.note(cannot, self.ports.prefix, offered(self.INSTALLS)),
                                                  doctor.note(cannot, self.ports.prefix, self.NEEDS), sync])
        self.inner: list[bool] = []
        self.fixed: bool | None = True

        def repair(_issue, _runner, _run_dir, _environ, show, *, confirm):
            """Ask the base package procedure's question once and record the answer in `inner`

            @param _issue    the finding
            @param _runner   the runner
            @param _run_dir  the run directory
            @param _environ  the environment
            @param show      prints a report line as it comes
            @param confirm   asks the user a question and returns the answer
            @returns         the report lines, and whether the repair worked
            """
            self.inner.append(confirm("The MacPorts base package procedure:\n  read ...\nRun it?"))
            show("  MacPorts 2.12.7 is installed at /opt/local, with its package list.")
            return ["MacPorts 2.12.7 is installed at /opt/local, with its package list."], self.fixed
        repairs = ("ports-platform-mismatch", "ports-built-for-other-os", "ports-registry-schema-update", cannot)
        self.mods = b.health_modules(ports=[self.cannot_run], ports_repairs=repairs, ports_repair=repair)

    def fix(self, **kw):
        """Run `--fix --target ports` on a terminal over the Mac with both managers, answering yes

        @param kw  the argument values that differ, such as `dry_run=True`
        @returns   the exit code
        """
        bundle = b.bundle(instances=[self.brew, self.ports])
        return self.doctor(bundle, self.mods, answers=[True], tty=True, fix=True, target="ports", **kw)

    def test_one_question_says_what_a_yes_does(self):
        code = self.fix()
        self.assertEqual(self.ctx.asked, ["Make this fix?"])
        self.assertEqual(self.inner, [True])
        self.assertEqual(self.output().splitlines()[1:], [
            "The installation you keep: MacPorts at /opt/local.",
            "doctor --fix offers 1 fix. It asks before it changes anything. `brew-ports doctor --target ports` lists "
            "everything that was found.",
            "It needs your password (sudo).",
            "", self.TITLE, f"  y {self.INSTALLS}; n changes nothing.", f"  {self.NEEDS}",
            "  MacPorts 2.12.7 is installed at /opt/local, with its package list.",
            "", "Made 1 fix.", "Next: brew-ports doctor --target ports   (it checks again and lists what is left)"])
        self.assertEqual(code, doctor.EXIT_OK)
        # The sync belongs to the repair, which runs it itself.
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(doctor_report.fixable([self.cannot_run]), 1)

    def test_a_repair_that_did_not_work_is_not_counted_as_a_fix(self):
        self.fixed = False
        code = self.fix()
        self.assertIn("\nMade no fix.\n", self.output())
        self.assertEqual(code, doctor.EXIT_FINDINGS)

    def test_a_repair_with_nothing_to_do_is_no_fix_and_no_finding(self):
        self.fixed = None
        code = self.fix()
        self.assertIn("\nMade no fix.\n", self.output())
        self.assertNotIn("Exit status", self.output())
        self.assertEqual(code, doctor.EXIT_OK)

    def test_dry_run_says_what_it_would_do_and_runs_nothing(self):
        self.fix(dry_run=True, yes=True)
        self.assertIn(f"\n{self.TITLE}\n  doctor --fix {self.INSTALLS}.\n  {self.NEEDS}\n", self.output())
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
        return self.doctor(bundle, b.health_modules(), fix=True, target="brew", yes=True)

    def test_a_clean_rescan_passes(self):
        self.assertEqual(self.run_fix("/usr/lib/libSystem.B.dylib"), doctor.EXIT_OK)
        reinstall = [c for c in self.fake.calls if "reinstall" in c]
        self.assertEqual(reinstall[0][-3:], ("reinstall", "--formula", "vim"))
        self.assertTrue(os.path.isfile(os.path.join(snapshot.brew_dir(self.fake.run_dir, self.brew.prefix),
                                                    snapshot.FORMULAE)))

    def test_a_reference_left_into_the_other_prefix_fails(self):
        self.assertEqual(self.run_fix(self.libz), doctor.EXIT_ACTION)
        self.assertIn("brew-ports: the commands ran, but a check afterwards still finds the problem: vim in Homebrew "
                      f"at {self.brew.prefix} uses libraries from another installation, and breaks when that one "
                      "goes\n", self.output())


class TargetTest(FixTest):
    """A Mac with Homebrew and MacPorts: `--fix` repairs the one `--target` names, and says what the other has too"""

    BROKEN = "While both copies are installed, one of them is broken"
    ONLY_KEPT = "doctor --fix repairs only the installation you keep"

    def setUp(self):
        super().setUp()
        self.ports = make_instance(Manager.PORTS, self.path("opt", "local"))
        self.at_brew, self.at_ports = f"Homebrew at {self.brew.prefix}", f"MacPorts at {self.ports.prefix}"
        self.link = self.brew_action("brew-unlinked-keg.jq.link", "link", "jq")
        self.unlinked = self.issue("brew-unlinked-keg", "jq", self.link, confirm_each=True)
        self.activate = port_action(self.ports, "doctor.ports-missing-file.curl.activate", "-f", "activate", "curl")
        self.missing = doctor._issue("ports-missing-file", Severity.HIGH, "Active file missing", "curl",
                                     self.ports.prefix, remedies=[self.activate], confirm_each=True)

    def both(self, mods=None, twice=(), **kw):
        """Run doctor over the Mac with both managers

        @param mods   the health modules; None for one finding with a fix in each installation
        @param twice  the packages that `duplicates.find` reports as installed twice
        @param kw     the command's argument values, and `answers` and `tty`
        @returns      the exit code
        """
        mods = mods or b.health_modules(brew=[self.unlinked], ports=[self.missing])
        with mock.patch("brew_ports.duplicates.find", return_value=list(twice)):
            return self.doctor(b.bundle(instances=[self.brew, self.ports]), mods, **kw)

    def test_fix_without_a_target_stops_before_any_check(self):
        needs = (f"brew-ports: {self.ONLY_KEPT}, so it needs to know which one that is: add --target brew for "
                 f"{self.at_brew} or --target ports for {self.at_ports}. `brew-ports recommend` compares a move in "
                 "each direction.\n")
        for kw in ({"fix": True}, {"dry_run": True}, {"fix": True, "yes": True}):
            self.assertEqual(self.both(**kw), doctor.EXIT_USAGE)
            self.assertEqual(self.output(), needs)
            self.assertEqual(self.fake.calls, [])
            self.assertFalse(os.path.exists(os.path.join(self.fake.run_dir.path, "doctor.json")))

    def test_only_the_installation_that_stays_is_repaired(self):
        code = self.both(fix=True, target="brew", yes=True)
        self.assertTrue(self.ran(self.link))
        self.assertFalse(self.ran(self.activate))
        self.assertEqual(self.output().splitlines()[1:], [
            f"The installation you keep: {self.at_brew}.",
            "doctor --fix offers 1 fix. --yes answers for you, except where a fix uninstalls a package or one of "
            "its versions, or deletes a cask's record or a stray file: that takes your own answer on a terminal. "
            "`brew-ports doctor --target brew` lists everything that was found.",
            "", f"Not offered: 1 fix in {self.at_ports}. {self.ONLY_KEPT}.",
            "", f"brew-unlinked-keg title ({self.at_brew})", f"  {binary_of(self.brew)} link jq ... ok",
            "", "Made 1 fix.", "Next: brew-ports doctor --target brew   (it checks again and lists what is left)",
            "Exit status 1: something needs a fix before a move, or is broken."])
        self.assertEqual(code, doctor.EXIT_FINDINGS)            # the port's missing file is still broken
        # With MacPorts as the one that stays, it is the other way round.
        self.both(fix=True, target="ports", yes=True)
        self.assertTrue(self.ran(self.activate))
        self.assertFalse(self.ran(self.link))
        self.assertIn(f"\nNot offered: 1 fix in {self.at_brew}. {self.ONLY_KEPT}.\n", self.output())

    def test_the_fixes_left_out_are_counted_in_one_line(self):
        second = self.path("usr", "local")
        intel = make_instance(Manager.BREW, second)
        stale = [doctor._issue("brew-unlinked-keg", Severity.LOW, f"{name} is not linked", name, second,
                               remedies=[self.brew_action(f"x.{name}", "link", name)], confirm_each=True)
                 for name in ("a", "b")]
        mods = b.health_modules(brew=stale, ports=[self.missing])
        with mock.patch("brew_ports.duplicates.find", return_value=[]):
            self.doctor(b.bundle(instances=[self.brew, intel, self.ports]), mods, fix=True, target="brew",
                        target_prefix=self.brew.prefix, yes=True)
        chosen = f"--target brew --target-prefix {self.brew.prefix}"
        self.assertEqual(self.output().splitlines()[2:], [
            f"No finding about {self.at_brew}, which you keep, has a fix that `doctor --fix` can make. `brew-ports "
            f"doctor {chosen}` lists what was found and what to do about it.",
            "", f"Not offered: 1 fix in {self.at_ports} and 2 fixes in Homebrew at {second}. {self.ONLY_KEPT}.",
            "Exit status 1: something needs a fix before a move, or is broken."])

    def test_no_terminal_names_the_command_that_answers(self):
        self.both(fix=True, target="brew")
        self.assertIn("There is no terminal to ask on, so it makes none of them: `brew-ports doctor --fix --target "
                      "brew --yes` answers for you.", self.output())
        self.assertFalse(self.ran(self.link))

    def test_no_fix_in_what_stays_says_so_and_names_what_is_left_out(self):
        self.both(b.health_modules(ports=[self.missing]), fix=True, target="brew")
        self.assertEqual(self.output().splitlines()[2:], [
            f"No finding about {self.at_brew}, which you keep, has a fix that `doctor --fix` can make. `brew-ports "
            "doctor --target brew` lists what was found and what to do about it.",
            "", f"Not offered: 1 fix in {self.at_ports}. {self.ONLY_KEPT}.",
            "Exit status 1: something needs a fix before a move, or is broken."])

    def test_what_stops_the_move_out_is_named_and_left_alone(self):
        code = "ports-damaged-registry"
        damaged = doctor._issue(code, Severity.HIGH, "MacPorts' record of installed ports cannot be read", None,
                                self.ports.prefix, remedies=[doctor.note(code, None, "Fix: restore it")],
                                blocks=(Blocks.TARGET, Blocks.REMOVE))
        self.both(b.health_modules(brew=[self.unlinked], ports=[damaged]), fix=True, target="brew", yes=True)
        self.assertIn("\n1 thing outside the installation you keep stops the move or a part of it:\n"
                      f"  MacPorts' record of installed ports cannot be read ({self.at_ports})\n"
                      f"      This stops uninstalling {self.at_ports} itself.\n"
                      "  `brew-ports doctor --target brew` lists what to do about it.\n", self.output())
        # What stops only that uninstall leaves the plan free to go ahead, so the report sends the user on to it.
        self.both(b.health_modules(ports=[damaged]), target="brew")
        self.assertIn("\nNext: brew-ports plan --target brew   (what is listed first stops only a part of the move; "
                      "the plan says what it leaves)\n", self.output())

    def test_a_finding_weighs_on_the_move_into_what_stays(self):
        code = "ports-registry-schema-update"
        stops = f"\n1 thing stops a move into {self.at_ports}, listed first.\n"
        for target, exit_code, said in (("brew", 0, "\nNothing stops a move."), (None, 1, stops), ("ports", 1, stops)):
            schema = doctor._issue(code, Severity.MEDIUM, "MacPorts needs one run as root", None, self.ports.prefix,
                                   remedies=[doctor.note(code, None, "Fix: run it")], blocks=(Blocks.TARGET,))
            self.assertEqual(self.both(b.health_modules(ports=[schema]), target=target), exit_code, target)
            self.assertIn(said, self.output(), target)
            self.assertIn({"brew": "\nNext: brew-ports plan --target brew\n",
                           "ports": "\nNext: fix what is listed first, then brew-ports doctor --target ports\n",
                           None: "\nNext: fix what is listed first, then brew-ports doctor\n"}[target], self.output())

    def test_weighing_keeps_the_blocks_of_an_installations_role(self):
        every = (Blocks.ANY, Blocks.TARGET, Blocks.UNINSTALL, Blocks.CASKS, Blocks.REMOVE)
        found = [doctor._issue("x", Severity.LOW, "t", None, prefix, blocks=every)
                 for prefix in (self.brew.prefix, self.ports.prefix, None, "/not/an/installation")]
        doctor_target.weigh_for(found, self.brew, [self.brew, self.ports])
        self.assertEqual([i.blocks for i in found], [
            (Blocks.ANY, Blocks.TARGET), (Blocks.ANY, Blocks.UNINSTALL, Blocks.CASKS, Blocks.REMOVE), every, every])

    def test_a_target_that_names_no_installation_stops(self):
        self.assertEqual(self.doctor(self.bundle(), b.health_modules(), target="ports"), doctor.EXIT_PREFLIGHT)
        self.assertEqual(self.output(), "brew-ports: MacPorts is not installed, so there is none to keep. `brew-ports "
                                        "doctor` without --target checks what this Mac has.\n")
        nowhere = self.path("nowhere")
        code = self.doctor(self.bundle(), b.health_modules(), target="brew", target_prefix=nowhere)
        self.assertEqual(code, doctor.EXIT_PREFLIGHT)
        self.assertEqual(self.output(), f"brew-ports: there is no Homebrew at {nowhere}: this Mac has {self.at_brew}\n")

    def test_two_of_a_manager_need_the_folder_of_the_one_that_stays(self):
        second = self.path("usr", "local")
        os.makedirs(second)
        intel = make_instance(Manager.BREW, second, identity=system.identity(second), owned_roots=(second,))
        mods = b.health_modules(brew=[self.unlinked])
        code = self.doctor(b.bundle(instances=[self.brew, intel]), mods, fix=True, target="brew", yes=True)
        self.assertEqual(code, doctor.EXIT_USAGE)
        self.assertEqual(self.output(), f"brew-ports: this Mac has {self.at_brew} and Homebrew at {second}: say which "
                                        "one you keep with --target-prefix\n")
        self.doctor(b.bundle(instances=[self.brew, intel]), mods, fix=True, target="brew",
                    target_prefix=self.brew.prefix, yes=True)
        self.assertTrue(self.ran(self.link))
        self.assertIn(f"\nNext: brew-ports doctor --target brew --target-prefix {self.brew.prefix}   (it checks "
                      "again and lists what is left)\n", self.output())
        # Without the folder, the Homebrew that `plan` moves into is the one that stays: here HOMEBREW_PREFIX's.
        self.doctor(b.bundle(instances=[self.brew, intel]), mods, fix=True, target="brew", yes=True,
                    environ={"HOME": "/Users/alice", "HOMEBREW_PREFIX": second})
        self.assertEqual(self.output().splitlines()[1], f"The installation you keep: Homebrew at {second}.")
        # The stop line names the options for each installation, and no comparison of managers where there is one.
        self.doctor(b.bundle(instances=[self.brew, intel]), mods, fix=True)
        self.assertEqual(self.output(), f"brew-ports: {self.ONLY_KEPT}, so it needs to know which one that is: add "
                         f"--target brew --target-prefix {self.brew.prefix} for {self.at_brew} or --target brew "
                         f"--target-prefix {second} for Homebrew at {second}.\n")
        other = make_instance(Manager.PORTS, self.path("opt", "ports"))
        code = self.doctor(b.bundle(instances=[self.ports, other]), b.health_modules(), target="ports")
        self.assertEqual(code, doctor.EXIT_USAGE)
        self.assertEqual(self.output(), f"brew-ports: this Mac has {self.at_ports} and MacPorts at {other.prefix}: "
                                        "say which one you keep with --target-prefix\n")

    def test_one_installation_needs_no_target_and_takes_one(self):
        for target in (None, "brew"):
            code = self.doctor(self.bundle(), b.health_modules(brew=[self.unlinked]), fix=True, target=target, yes=True)
            self.assertEqual(code, doctor.EXIT_OK)
            self.assertTrue(self.ran(self.link))
            self.assertNotIn("The installation you keep", self.output())
            self.assertIn("\nNext: brew-ports doctor   (it checks again and lists what is left)\n", self.output())

    WHY = ("      While a package is installed twice, one copy is broken: typing its command or building with it "
           "finds only one of the two.")

    def test_the_report_lists_what_is_installed_twice(self):
        twice = [duplicates.Double(self.ports, "gsed", "gnu-sed", ["sed-tools"]),
                 duplicates.Double(self.ports, "bash", "bash", held=["is your login shell"]),
                 duplicates.Double(self.ports, "jq", "jq", version="@1.7.1_0")]
        code = self.both(b.health_modules(), twice, target="brew")
        self.assertEqual(self.output().splitlines()[1:], [
            f"The installation you keep: {self.at_brew}.",
            "", "Nothing stops a move. 1 thing is broken or at risk.",
            "", "Broken or at risk (1)",
            f"  3 packages of {self.at_ports} are installed in {self.at_brew} too",
            f"      gsed (gnu-sed in {self.at_brew}), bash, jq",
            self.WHY,
            f"      Fix: brew-ports plan --target brew (plans the move out of {self.at_ports}, which uninstalls "
            "these copies, except those that a package staying there still needs)",
            # The example is a copy that nothing ties there: no package needs it, and it is not the login shell.
            "      To uninstall one of them yourself once the copy you keep works, such as jq: sudo "
            f"{binary_of(self.ports)} uninstall jq @1.7.1_0",
            "", "Next: brew-ports plan --target brew",
            "Exit status 1: something needs a fix before a move, or is broken."])
        self.assertEqual(code, doctor.EXIT_FINDINGS)
        with open(os.path.join(self.fake.run_dir.path, "doctor.json"), encoding="utf-8") as fh:
            result = model.from_json(model.DoctorResult, fh.read())
        self.assertEqual([(i.code, i.severity, i.instance_prefix) for i in result.issues],
                         [("env-installed-twice", Severity.HIGH, self.ports.prefix)])
        self.assertEqual(result.target_prefix, self.brew.prefix)

    def test_copies_that_cannot_go_alone_are_left_to_the_plan(self):
        """No copy is free, so no command for one of them; a `port` that cannot run needs `--delete`"""
        tied = [duplicates.Double(self.ports, "bash", "bash", held=["is your login shell"])]
        self.both(b.health_modules(), tied, target="brew")
        self.assertNotIn("To uninstall one of them yourself", self.output())
        self.ports.drivable = False
        self.both(b.health_modules(), [duplicates.Double(self.ports, "jq", "jq")], target="brew")
        self.assertEqual(self.output().splitlines()[7:11], [
            "      jq", self.WHY,
            f"      Fix: brew-ports plan --target brew --delete {self.ports.prefix} (plans the move out of "
            f"{self.at_ports}, which deletes that installation whole afterwards, as its `port` command cannot run)",
            ""])

    def test_a_finding_about_another_installation_offers_no_fix(self):
        self.both(target="brew")
        self.assertIn(f"\n  brew-unlinked-keg title ({self.at_brew})\n      evidence of brew-unlinked-keg\n"
                      f"      Fix: brew-ports doctor --fix --target brew (asks, then runs `{binary_of(self.brew)} "
                      "link jq`)\n", self.output())
        self.assertIn(f"\n  Active file missing ({self.at_ports})\n      No fix offered: {self.ONLY_KEPT}.\n",
                      self.output())
        self.assertNotIn("--target ports", self.output())
        # Until the user has chosen, each fix says which installation it is for.
        self.both()
        self.assertIn(f"\n      Fix, if you keep {self.at_ports}: brew-ports doctor --fix --target ports (asks, then "
                      f"runs `sudo {binary_of(self.ports)} -N -f activate curl`)\n", self.output())
        self.assertIn(f"\n      Fix, if you keep {self.at_brew}: brew-ports doctor --fix --target brew (asks, then ",
                      self.output())

    def test_copies_that_could_not_be_looked_for_are_a_check_not_run(self):
        """Without the package list of the installation that stays, no copy found would prove nothing"""
        bundle = b.bundle(instances=[self.brew, self.ports])
        code = self.doctor(bundle, b.health_modules(), target="brew")
        self.assertEqual(self.output().splitlines()[2:], [
            "", "No problems found.", "", "Checks that could not run",
            f"  Which packages are installed twice: this Mac has no package list for {self.at_brew}",
            "", "Next: brew-ports plan --target brew"])
        self.assertEqual(code, doctor.EXIT_OK)

    def test_without_a_target_nothing_says_which_copy_is_the_other(self):
        self.both(b.health_modules(), [duplicates.Double(self.ports, "jq", "jq")])
        self.assertNotIn("installed twice", self.output())
        self.assertNotIn("The installation you keep", self.output())

    def test_a_repair_warns_of_the_copy_elsewhere(self):
        port, brew = binary_of(self.ports), binary_of(self.brew)
        shown = f"\nbrew-unlinked-keg title ({self.at_brew})\n  y runs `{brew} link jq`; n changes nothing.\n"
        broken = make_instance(Manager.PORTS, self.ports.prefix, drivable=False)
        for double, warning in (
                (duplicates.Double(self.ports, "jq", "jq", version="@1.7.1_0"),
                 f"jq is also installed in {self.at_ports}. {self.BROKEN}. Once this fix has worked, uninstall the "
                 f"other copy: sudo {port} uninstall jq @1.7.1_0"),
                (duplicates.Double(self.ports, "jq-devel", "jq"),
                 f"jq is also installed in {self.at_ports}, as jq-devel. {self.BROKEN}. Once this fix has worked, "
                 f"uninstall the other copy: sudo {port} uninstall jq-devel"),
                (duplicates.Double(self.ports, "jq", "jq", ["gojq", "yq"]),
                 f"jq is also installed in {self.at_ports}. {self.BROKEN}. Leave the other copy to the move, because "
                 "it is needed by 2 packages there (gojq, yq): brew-ports plan --target brew"),
                (duplicates.Double(self.ports, "jq", "jq", held=["is your login shell", "has the service org.jq"]),
                 f"jq is also installed in {self.at_ports}. {self.BROKEN}. Leave the other copy to the move, because "
                 "it is your login shell and has the service org.jq: brew-ports plan --target brew"),
                (duplicates.Double(broken, "jq", "jq"),
                 f"jq is also installed in {self.at_ports}. {self.BROKEN}. Leave the other copy to the move, because "
                 "it cannot be uninstalled while the `port` command there does not run: brew-ports plan --target "
                 f"brew --delete {self.ports.prefix}")):
            self.both(twice=[double], fix=True, target="brew", answers=[True], tty=True)
            # The warning is the last line above the question; the command follows the answer.
            self.assertIn(f"{shown}  {warning}\n  {brew} link jq ... ok\n", self.output())
            self.assertEqual(self.ctx.asked, ["Make this fix?"])

    def test_a_copy_is_named_once_in_a_run(self):
        """A second fix about the package, offered after a no to the first, does not repeat the warning"""
        again = self.issue("brew-broken-linkage", "jq", self.brew_action("brew-broken-linkage.jq.reinstall",
                                                                         "reinstall", "jq"), confirm_each=True)
        mods = b.health_modules(brew=[self.unlinked, again])
        self.both(mods, [duplicates.Double(self.ports, "jq", "jq")], fix=True, target="brew", answers=[False, True],
                  tty=True)
        self.assertEqual(self.ctx.asked, ["Make this fix?"] * 2)
        self.assertEqual(self.output().count("jq is also installed in"), 1)
        self.assertEqual((self.ran(self.link), self.ran(again.remedies[0])), (False, True))

    def test_fixes_that_take_one_answer_carry_the_warning(self):
        """In a dry run and under --yes alike, although --yes prints no list of them"""
        renamed = [self.issue("brew-renamed-keg", name, self.brew_action(f"brew-renamed-keg.{name}.migrate",
                                                                         "migrate", name), auto_fix=True)
                   for name in ("jq", "wget")]
        mods = b.health_modules(brew=renamed)
        twice = [duplicates.Double(self.ports, "jq", "jq")]
        warning = f"jq is also installed in {self.at_ports}. {self.BROKEN}. Once this fix has worked, uninstall"
        self.both(mods, twice, fix=True, dry_run=True, target="brew")
        self.assertIn(f"\n  brew-renamed-keg title ({self.at_brew})\n      runs `{binary_of(self.brew)} migrate jq`\n"
                      f"      {warning}", self.output())
        self.both(mods, twice, fix=True, target="brew", yes=True)
        self.assertIn(f"\nbrew-renamed-keg title ({self.at_brew})\n  {warning}", self.output())
        self.assertEqual(self.output().count("is also installed in"), 1)

    def test_a_removal_and_another_package_get_no_warning(self):
        other = [duplicates.Double(self.ports, "wget", "wget")]
        self.both(twice=other, fix=True, target="brew", yes=True)
        self.assertNotIn("is also installed", self.output())
        mods = b.health_modules(brew=[self.unlinked], brew_terminal=["brew-unlinked-keg"])
        self.both(mods, [duplicates.Double(self.ports, "jq", "jq")], fix=True, target="brew", answers=[True], tty=True)
        self.assertNotIn("is also installed", self.output())

    def test_json_lists_what_is_installed_twice_with_the_findings(self):
        code = self.both(twice=[duplicates.Double(self.ports, "jq", "jq")], json=True, target="brew")
        data = json.loads(self.ctx.console.stream.getvalue())
        self.assertEqual([i["code"] for i in data["issues"]],
                         ["brew-unlinked-keg", "ports-missing-file", "env-installed-twice"])
        self.assertEqual(code, doctor.EXIT_FINDINGS)


if __name__ == "__main__":
    unittest.main()

"""`brew-ports apply` end to end against FakeRunner and a synthetic host

Both targets, dry runs, `--stop-after`, refused and stale plans, resumes, the gate, interrupts and `report.md`.
"""

import contextlib
import io
import json
import os
import sys
import unittest
from unittest import mock

from brew_ports import cli, doctor, envclean, exec_run, executor, model, remove_manager, runner as r, snapshot, state
from brew_ports.macports import actions as mp_actions
from brew_ports.model import Blocks, Severity
from tests.unit.fixtures.executor import builders as b
from tests.unit.fixtures.macports import builders as mb
from tests.unit.helpers import TempDirTest, make_package


class ApplyTest(TempDirTest):
    """A synthetic host, the stand-ins for verify, envclean and remove_manager, and `apply`"""

    # A scenario sets these before a test reads them; `apply` sets the context of its command.
    ctx: b.FakeContext
    target: model.Instance
    source: model.Instance
    plist: str
    mappings: list[model.Mapping]
    removal: dict[str, list[tuple[str, str]]]
    install: model.Action
    plan: model.Plan
    plan_path: str

    def setUp(self):
        super().setUp()
        self.sd = self.state_dir()
        self.host = b.Host()
        self.responder = b.Responder(self.sd)
        self.runners = []
        self.modules = {"brew_ports.verify": b.verify_module(), "brew_ports.envclean": b.envclean_module(),
                        "brew_ports.remove_manager": b.remove_manager_module()}
        b.FakeRootFiles.writes = []
        self.issues = []
        b.patches(self, self.host)

    def factory(self, ctx, run_dir):
        """Make the runner of a command: the responder answers it, and `runners` keeps it

        @param ctx      the command's context
        @param run_dir  the run directory
        @returns        the runner
        """
        fake = r.FakeRunner(default=self.responder, console=ctx.console, environ=dict(ctx.environ), run_dir=run_dir)
        self.runners.append(fake)
        return fake

    def apply(self, **kw):
        """Run `apply` on the test's plan, or on the run `resume` names, with the stand-ins in `sys.modules`

        @param kw  the command line's values, such as `dry_run=True`; `answers` and `tty` for the terminal
        @returns   the exit code
        """
        kw.setdefault("plan", None if kw.get("resume") else self.plan_path)
        ctx = b.context(self.sd, **kw)
        with mock.patch.dict(sys.modules, self.modules), \
                mock.patch("brew_ports.doctor.detect_all", return_value=list(self.issues)):
            code = executor.cmd_apply(ctx, make_runner=self.factory)
        self.ctx = ctx
        return code

    @property
    def out(self):
        """Return what the last command printed

        @returns  its standard output, then its standard error
        """
        return self.ctx.console.text

    @property
    def run_dir(self):
        """Return the run directory of the last command

        @returns  the run directory
        """
        return self.runners[-1].run_dir

    def results(self, run_dir=None):
        """Return the result lines a run journaled

        @param run_dir  the run directory; None for the last command's
        @returns        each result by `(phase, action id)`, the last one winning
        """
        entries = (run_dir or self.run_dir).journal.entries()
        return {(e["phase"], e["action_id"]): e["result"] for e in entries if "result" in e}

    def entry(self, action_id, run_dir=None):
        """Return the journal entries of one action

        @param action_id  the action's id
        @param run_dir    the run directory; None for the last command's
        @returns          the entries, in journal order
        """
        return [e for e in (run_dir or self.run_dir).journal.entries() if e.get("action_id") == action_id]

    # Scenario A: MacPorts to Homebrew --------------------------------------------------------

    def scenario_brew(self):
        """Plan a move of dnsmasq (with a loaded startup item), jq and oniguruma from MacPorts to Homebrew"""
        target = b.brew_prefix(self.tmp, "opt/homebrew")
        source = b.ports_prefix(self.tmp, "opt/local", rows=[
            mb.port(1, "dnsmasq", "2.90"), mb.port(2, "jq", "1.7.1"), mb.port(3, "oniguruma", "6.9.9", requested=0)],
            deps=[(2, "oniguruma")])
        self.target, self.source = b.brew(target), b.ports(source)
        program = os.path.join(source, "sbin", "dnsmasq")
        self.plist = b.plist(self.tmp, "org.macports.dnsmasq", program)
        self.responder.loaded["org.macports.dnsmasq"] = "system"
        self.responder.programs["org.macports.dnsmasq"] = program
        self.responder.versions = {"dnsmasq": "2.90", "jq": "1.7.1", "oniguruma": "6.9.9"}
        self.responder.pours = {"jq": [("oniguruma", "6.9.9")]}
        pkgs = {n: make_package(n, "port", source, version=v + "_0", spec_args=[n, f"@{v}_0"])
                for n, v in (("dnsmasq", "2.90"), ("jq", "1.7.1"), ("oniguruma", "6.9.9"))}
        self.host.instances = [self.target, self.source]
        self.host.packages = list(pkgs.values())
        self.host.services = [b.service("org.macports.dnsmasq", self.plist, source, "dnsmasq", "port")]
        self.host.catalogues[target] = b.FakeCatalogue(versions=dict(self.responder.versions))
        self.host.environment = {"login_shell": "/bin/zsh", "files": [], "etc_paths": []}
        self.mappings = [b.mapping(pkgs["dnsmasq"], "formula", "dnsmasq", version="2.90"),
                         b.mapping(pkgs["jq"], "formula", "jq", version="1.7.1")]
        self.removal = {source: [("port", "dnsmasq"), ("port", "jq"), ("port", "oniguruma")]}
        self.install = b.install_action(self.target, "3.install.bottled", ["dnsmasq", "jq"])
        self.save_plan(b.plan(self.target, [self.source], mappings=self.mappings, removal=self.removal,
                              phase3=[self.install]))

    # Scenario B: Homebrew to MacPorts --------------------------------------------------------

    def scenario_ports(self):
        """Plan a move of wget, its dependency libidn2 and the cask iterm2 (`--casks drop`) to MacPorts"""
        target = b.ports_prefix(self.tmp, "opt/local")
        source = b.brew_prefix(self.tmp, "usr/local")
        b.keg(source, "wget", "1.24.5", deps=["libidn2"], exes=["wget"])
        b.keg(source, "libidn2", "2.3.7", requested=False)
        b.caskroom(source, "iterm2", "3.5")
        self.target, self.source = b.ports(target), b.brew(source)
        wget = make_package("wget", "formula", source, deps=["libidn2"])
        self.host.instances = [self.target, self.source]
        self.host.packages = [wget, make_package("libidn2", "formula", source, requested=False),
                              make_package("iterm2", "cask", source)]
        self.host.environment = {"login_shell": "/bin/zsh", "files": [], "etc_paths": []}
        self.responder.fail = {"wget": 1}
        self.responder.versions = {"wget": "1.24.5"}
        self.install = mp_actions.install(self.target, "arm64", "3.install.wget", "wget", [], homebrew_present=True)
        self.save_plan(b.plan(self.target, [self.source],
                              mappings=[b.mapping(wget, "port", "wget", version="1.24.5_0")],
                              removal={source: [("cask", "iterm2"), ("formula", "libidn2"), ("formula", "wget")]},
                              phase3=[self.install], casks="drop"))

    def save_plan(self, plan):
        """Write a plan to `plan.json` in the temporary directory, as the plan `apply` takes

        @param plan  the plan
        """
        self.plan = plan
        self.plan_path = b.write_plan(self.path("plan.json"), plan)


class FullRunTest(ApplyTest):
    """Whole runs to a Homebrew and to a MacPorts target"""

    def test_homebrew_target(self):
        self.scenario_brew()
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        results = self.results()
        for key in ((3, "3.install.bottled"), (5, "5.stop.org.macports.dnsmasq"), (5, "5.uninstall.ports")):
            self.assertEqual(results.get(key), "ok", key)
        self.assertEqual(sorted(n for _, n in results if n.endswith(".complete")),
                         [f"{n}.complete" for n in (0, 1, 2, 3, 4, 5, 7, 8)])
        self.assertEqual(self.responder.ran("port", "uninstall"),
                         [[self.source.binary, "-N", "uninstall", "dnsmasq", "@2.90_0", "jq", "@1.7.1_0", "oniguruma",
                           "@6.9.9_0"]])
        self.assertEqual(b.port_names(self.source.prefix), [])
        self.assertFalse(os.path.exists(self.plist))
        verbs = [" ".join(tail[:3]) for _, tail in self.responder.log]
        bootout = next(i for i, v in enumerate(verbs) if v.startswith("/bin/launchctl bootout"))
        uninstall = verbs.index(f"{self.source.binary} -N uninstall")
        removal = next(i for i, v in enumerate(verbs) if v.startswith("/bin/rm -f"))
        self.assertLess(bootout, uninstall)
        self.assertLess(uninstall, removal)
        self.assertTrue(self.entry("3.install.bottled.listing"))
        self.assertTrue(snapshot.is_complete(self.run_dir))
        self.assertEqual((self.sd.dirty() or {}).get("run_id"), self.run_dir.run_id)
        self.assertEqual(self.modules["brew_ports.verify"].calls, [True, False])
        self.assertEqual(self.modules["brew_ports.envclean"].journals[0].path, self.run_dir.journal.path)
        with open(self.run_dir.sub("plan.json"), encoding="utf-8") as fh:
            self.assertEqual(model.from_json(model.Plan, fh.read()).target_prefix, self.target.prefix)
        self.assertTrue(os.path.isfile(self.run_dir.sub("report.md")))

    def test_macports_target(self):
        self.scenario_ports()
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        installs = self.responder.ran("port", "install")
        self.assertEqual([a[1:3] for a in installs], [["-N", "-b"], ["-N", "-t"]])
        self.assertTrue(self.entry("3.install.wget.retry"))
        self.assertEqual(self.results()[(3, "3.install.wget")], "ok")
        uninstalls = self.responder.ran("brew", "uninstall")
        self.assertEqual([u[2:] for u in uninstalls], [["--cask", "--force", "iterm2"],
                                                       ["--formula", "--force", "libidn2", "wget"]])
        self.assertEqual(os.listdir(os.path.join(self.source.prefix, "Cellar")), [])
        self.assertEqual(os.listdir(os.path.join(self.source.prefix, "Caskroom")), [])
        self.assertEqual(b.port_names(self.target.prefix), ["wget"])


class DryRunTest(ApplyTest):
    """`apply --dry-run`: every phase printed, nothing run, no run to resume"""

    def test_prints_every_phase_and_runs_nothing(self):
        self.scenario_brew()
        self.assertEqual(self.apply(dry_run=True), executor.EXIT_OK, self.out)
        self.assertEqual(self.runners[-1].calls, [])
        self.assertFalse(os.path.exists(self.sd.dirty_path))
        self.assertFalse(os.path.exists(self.run_dir.sub("plan.json")))
        self.assertFalse(os.path.exists(snapshot.snapshot_dir(self.run_dir)))
        for number in (0, 1, 2, 3, 4, 5, 7, 8):
            self.assertIn(f"== phase {number}:", self.out)
        for text in ("3.install.bottled", "5.uninstall.ports", "5.stop.org.macports.dnsmasq",
                     "nothing was changed and no marker was touched"):
            self.assertIn(text, self.out)
        self.assertEqual(b.port_names(self.source.prefix), ["dnsmasq", "jq", "oniguruma"])
        self.assertEqual(self.modules["brew_ports.verify"].calls, [])
        self.assertFalse(self.runners[-1].sudo_ready)
        self.assertNotIn(".complete", "".join(e.get("action_id", "") for e in self.run_dir.journal.entries()))

    def test_a_dry_run_cannot_be_resumed(self):
        self.scenario_brew()
        self.apply(dry_run=True)
        dry = self.run_dir.run_id
        self.assertEqual(self.apply(resume=dry), executor.EXIT_USAGE)
        self.assertIn("is not an apply run", self.out)


class StopAndResumeTest(ApplyTest):
    """`--stop-after`, interrupted installs and the rules that refuse or allow a resume"""

    def test_stop_after_then_resume_skips_passed_retry(self):
        self.scenario_ports()
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK, self.out)
        first = self.run_dir
        self.assertEqual(self.results().get((3, "3.complete")), "ok")
        self.assertNotIn((4, "4.complete"), self.results())
        self.assertIn(f"apply --resume {first.run_id}` continues", self.out)
        self.assertEqual(sorted(os.listdir(os.path.join(self.source.prefix, "Cellar"))), ["libidn2", "wget"])
        self.responder.log.clear()
        self.assertEqual(self.apply(resume=first.run_id), executor.EXIT_OK, self.out)
        self.assertEqual(self.run_dir.path, first.path)
        self.assertEqual(self.responder.ran("port", "install"), [])
        self.assertIn("(ok in an earlier attempt: skipped)", self.out)
        self.assertEqual(len(self.responder.ran("brew", "uninstall")), 2)
        self.assertEqual(self.responder.ran("tmutil"), [])          # phase 1 is not taken again

    def test_interrupted_install_resumes_as_reinstall(self):
        self.scenario_brew()

        def killed(tail):
            if "--formula" in tail and "install" in tail:
                self.responder.answer_brew([tail[0], "install", "--formula", "jq"], "install")
                self.runners[-1].note_sigint()
                return r.FakeResponse(exit=130)
            return None
        self.responder.hooks["install"] = killed
        self.assertEqual(self.apply(), executor.EXIT_ACTION, self.out)
        first = self.run_dir
        self.assertIn("was interrupted", self.out)
        self.assertNotIn((3, "3.install.bottled"), self.results())
        self.assertEqual(self.entry("3.install.bottled")[0]["exit"], 130)
        self.assertEqual(self.responder.ran("port", "uninstall"), [])
        del self.responder.hooks["install"]
        self.responder.log.clear()
        self.assertEqual(self.apply(resume=first.run_id), executor.EXIT_OK, self.out)
        brew = [tail[1:] for tail in self.responder.ran("brew") if tail[1] in ("install", "reinstall")]
        self.assertEqual(brew, [["reinstall", "--formula", "jq", "oniguruma"],
                                ["install", "--formula", "dnsmasq"]])
        self.assertEqual(self.results()[(3, "3.install.bottled")], "ok")

    def test_resume_refused_after_another_command(self):
        self.scenario_ports()
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK)
        first = self.run_dir.run_id
        self.sd.touch_dirty("20261113-120000-bbbbbb", "doctor --fix")
        later = os.stat(self.sd.dirty_path).st_mtime + 10
        os.utime(self.sd.dirty_path, (later, later))
        self.assertEqual(self.apply(resume=first), executor.EXIT_PREFLIGHT)
        self.assertIn("re-plan", self.out)
        self.assertIn("doctor --fix", self.out)

    def test_an_unknown_run_is_a_usage_error(self):
        self.scenario_ports()
        self.assertEqual(self.apply(resume="20990101-000000-cccccc"), executor.EXIT_USAGE)


class RefusalTest(ApplyTest):
    """Plans that exit 3 before a run exists: a refused plan and one older than the dirty marker"""

    def test_a_refused_plan_file_exits_3(self):
        path = self.write_file("plan-refused.json", {"refused": {"exit": 1, "reasons": ["pinned jq"]}, "plan": None})
        self.plan_path = path
        self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn("re-plan", self.out)
        self.assertIn("pinned jq", self.out)
        self.assertEqual(self.sd.run_ids(), [])

    def test_a_plan_older_than_the_marker_exits_3(self):
        self.scenario_ports()
        self.sd.touch_dirty("20261113-110000-dddddd", "rollback")
        old = os.stat(self.sd.dirty_path).st_mtime - 100
        os.utime(self.plan_path, (old, old))
        self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn("re-plan", self.out)
        self.assertIn("rollback", self.out)
        self.assertEqual(self.sd.run_ids(), [])

    def write_file(self, name, data):
        """Write a JSON file in the temporary directory

        @param name  the file's name
        @param data  its JSON value
        @returns     the file's path
        """
        path = self.path(name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return path


class PreflightTest(ApplyTest):
    """Phase 0: blocking findings, the phase 6 exemption, undrivable sources, refused targets and sudo"""

    def issue(self, code, prefix, blocks, severity=Severity.HIGH):
        """Return a finding whose one remedy is a manual note

        @param code      the finding's name
        @param prefix    the prefix of its instance
        @param blocks    what it blocks
        @param severity  its severity
        @returns         the finding
        """
        return doctor._issue(code, severity, f"{code} title", None, prefix, evidence=["evidence"],
                             remedies=[doctor.note(code, None, "repair it")], blocks=blocks)

    def test_blocking_finding_exits_3_first(self):
        self.scenario_brew()
        self.issues = [self.issue("ports-damaged-registry", self.source.prefix, (Blocks.UNINSTALL,))]
        self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn("blocked by ports-damaged-registry", self.out)
        self.assertFalse(os.path.exists(self.sd.dirty_path))
        self.assertFalse(snapshot.is_complete(self.run_dir))
        self.assertFalse(self.runners[-1].sudo_ready)

    def test_source_in_phase_6_deletion_is_exempt(self):
        self.scenario_brew()
        self.assertEqual(self.apply(stop_after=0), executor.EXIT_OK, self.out)
        first = self.run_dir
        tag = state.slug(self.source.prefix)
        first.journal.append({"phase": 6, "action_id": f"6.identity.{tag}", "prefix": self.source.prefix})
        self.issues = [self.issue("ports-damaged-registry", self.source.prefix, (Blocks.UNINSTALL,))]
        self.host.instances = [self.target]                  # the scan cannot find the half-deleted prefix
        self.assertEqual(self.apply(resume=first.run_id, stop_after=0), executor.EXIT_PREFLIGHT)
        self.assertIn("blocked by ports-damaged-registry", self.out)     # the identity alone deletes nothing
        first.journal.append({"phase": 6, "action_id": f"6.delete.{tag}", "argv": ["/bin/rm", "-rf"], "exit": 0})
        self.assertEqual(self.apply(resume=first.run_id, stop_after=0), executor.EXIT_OK, self.out)

    def test_low_disk_space_skipped_after_phase_3(self):
        self.scenario_ports()
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK)
        first = self.run_dir.run_id
        self.issues = [self.issue("system-low-disk-space", self.target.prefix, (Blocks.ANY,))]
        self.assertEqual(self.apply(resume=first, stop_after=0), executor.EXIT_OK, self.out)
        later = os.stat(self.sd.dirty_path).st_mtime + 10
        os.utime(self.plan_path, (later, later))             # a new plan, made after the run
        self.assertEqual(self.apply(stop_after=0), executor.EXIT_PREFLIGHT)
        self.assertIn("blocked by system-low-disk-space", self.out)

    def test_undrivable_source_names_the_repair(self):
        self.scenario_brew()
        self.source.drivable = False
        self.source.usability = model.Usability.DAMAGED_REGISTRY
        self.issues = [self.issue("ports-damaged-registry", self.source.prefix, ())]
        self.issues[0].confirm_each = True
        self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn(f"the source {self.source.prefix} cannot be driven (damaged-registry)", self.out)
        self.assertIn("doctor --fix` repairs it (ports-damaged-registry)", self.out)

    def test_a_refused_homebrew_target_exits_3(self):
        self.scenario_brew()
        self.host.catalogues[self.target.prefix].refusals["jq"] = {"date": "2026-11-01", "because": "unmaintained",
                                                                   "replacement_formula": "gojq"}
        self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn("Homebrew refuses to install formula jq: disabled since 2026-11-01 (unmaintained)", self.out)
        self.assertIn("--map jq=gojq; re-plan", self.out)

    def test_sudo_that_caches_nothing_exits_3(self):
        self.scenario_brew()
        with mock.patch.object(r.FakeRunner, "sudo_preflight", side_effect=r.PreflightError("no ticket")):
            self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn("no ticket", self.out)
        self.assertFalse(os.path.exists(self.sd.dirty_path))


class GateTest(ApplyTest):
    """Phase 4: a failed gate stops the run before any removal"""

    def test_a_failed_gate_exits_4_and_removes_nothing(self):
        self.scenario_brew()
        self.modules["brew_ports.verify"] = b.verify_module({True: [("installed", "jq -> jq", "jq is not installed")]})
        self.assertEqual(self.apply(), executor.EXIT_ACTION)
        for text in ("the gate failed: no source package was removed", "--keep jq", f"rollback {self.run_dir.run_id}",
                     "FAIL jq -> jq (replacements installed): jq is not installed"):
            self.assertIn(text, self.out)
        self.assertEqual(self.responder.ran("port", "uninstall"), [])
        self.assertEqual(b.port_names(self.source.prefix), ["dnsmasq", "jq", "oniguruma"])
        self.assertFalse([k for k in self.results() if k[0] == 5])


class InterruptTest(ApplyTest):
    """A Ctrl-C during phase 5: the services come back while their packages are still installed"""

    def test_ctrl_c_in_uninstall_restarts_services(self):
        self.scenario_brew()

        def interrupted(tail):
            if tail[2] == "uninstall" and len(tail) > 5:      # the batch, not a retry
                b.drop_port(self.source.prefix, "jq", "@1.7.1_0")
                b.drop_port(self.source.prefix, "oniguruma", "@6.9.9_0")
                self.runners[-1].note_sigint()
                return r.FakeResponse(exit=1)
            return None
        self.responder.hooks["uninstall"] = interrupted
        self.assertEqual(self.apply(), executor.EXIT_ACTION)
        self.assertEqual(self.entry("5.uninstall.ports")[0]["exit"], 1)
        self.assertEqual(self.responder.ran("port", "uninstall")[1:], [])        # no retry after the interrupt
        self.assertEqual([t[-2:] for t in self.responder.ran("port", "load")], [["load", "dnsmasq"]])
        self.assertIn("org.macports.dnsmasq started again", self.out)
        self.assertIn("was interrupted", self.out)
        self.assertIn(f"apply --resume {self.run_dir.run_id}` continues", self.out)
        self.assertNotIn((5, "5.complete"), self.results())
        self.assertTrue(os.path.exists(self.plist))

    def test_ctrl_c_after_uninstall_keeps_the_plist(self):
        self.scenario_brew()

        def finished(tail):
            self.responder.answer_port(tail, "uninstall")
            self.runners[-1].note_sigint()
            return r.FakeResponse(exit=0)
        self.responder.hooks["uninstall"] = finished
        self.assertEqual(self.apply(), executor.EXIT_ACTION)
        self.assertEqual(self.entry("5.uninstall.ports")[0]["exit"], 0)
        self.assertEqual(self.responder.ran("rm"), [])
        self.assertEqual(self.responder.ran("port", "load"), [])           # its package is gone
        self.assertTrue(os.path.exists(self.plist))


class MarkerTest(ApplyTest):
    """The dirty marker and the phase confirmations"""

    def test_marker_written_before_first_change(self):
        self.scenario_brew()
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        seen = self.responder.marker
        first = next(i for i, (word, _) in enumerate(seen) if word == "brew install")
        self.assertTrue(seen[first][1])
        self.assertEqual([word for word, there in seen[:first] if there], [])
        self.assertIn("tmutil localsnapshot", [word for word, _ in seen[:first]])

    def test_declined_phase_exits_4_and_keeps_plan(self):
        self.scenario_brew()
        self.assertEqual(self.apply(yes=False), executor.EXIT_ACTION)
        self.assertIn("phase 1 was not confirmed (no terminal: --yes answers every phase)", self.out)
        self.assertFalse(os.path.exists(self.sd.dirty_path))
        keepalive = (r.SUDO, "-n", "-v")                       # phase 0's first keepalive
        self.assertEqual([c for c in self.runners[-1].calls if c != keepalive], [])

    def test_a_no_at_a_later_phase_on_a_terminal(self):
        self.scenario_brew()
        self.assertEqual(self.apply(yes=False, tty=True, answers=[True, False]), executor.EXIT_ACTION)
        self.assertEqual(len(self.ctx.asked), 2)
        self.assertIn("Run phase 3 (install)?", self.ctx.asked[1])
        self.assertEqual(self.responder.ran("brew", "install"), [])
        self.assertIn("apply --resume", self.out)


class PhaseSixTest(ApplyTest):
    """Phase 6 through the stand-in for `remove_manager`"""

    def plan_with_phase6(self):
        """Plan the move of scenario A with `--remove-manager` for its MacPorts source"""
        self.scenario_brew()
        note = model.Action(action_id=f"6.note.{state.slug(self.source.prefix)}.checks", kind="note", argv=[],
                            sudo=False, description="the checks", manual=True)
        self.save_plan(b.plan(self.target, [self.source], mappings=self.mappings, removal=self.removal,
                              phase3=[self.install], phase6=[note], remove=[self.source.prefix]))

    def test_remove_manager_runs_after_phase_5(self):
        self.plan_with_phase6()
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        call, = self.modules["brew_ports.remove_manager"].calls
        self.assertEqual((call["resumed"], call["phase"], call["run_id"], call["yes"]),
                         (False, 6, self.run_dir.run_id, True))
        self.assertNotIn("phase 6 done", self.out)              # remove_manager prints its own lines
        with open(self.run_dir.sub("report.md"), encoding="utf-8") as fh:
            self.assertIn("phase 6 done", fh.read())
        self.assertEqual(self.results().get((6, "6.complete")), "ok")
        # Phase 7 weighs a scan taken after phase 6: an undrivable source's packages go only then.
        survivors_bundle, = self.modules["brew_ports.envclean"].bundles
        self.assertIsNot(survivors_bundle, call["bundle"])
        self.assertEqual(self.host.scans, 5)                 # phases 0, 4, 6, 7 and 8

    def test_a_resumed_phase_6_says_so(self):
        self.plan_with_phase6()
        self.assertEqual(self.apply(stop_after=5), executor.EXIT_OK, self.out)
        self.assertEqual(self.apply(resume=self.run_dir.run_id), executor.EXIT_OK, self.out)
        self.assertEqual([c["resumed"] for c in self.modules["brew_ports.remove_manager"].calls], [True])

    def test_failed_phase_6_check_keeps_its_lines(self):
        self.plan_with_phase6()
        lines = [f"checks of {self.source.prefix}: pid 77 runs {self.source.prefix}/bin/redis"]
        failure = remove_manager.Stopped(r.Result("6.check.lsof.x", 1, None, None), "a process uses the prefix", lines)
        self.modules["brew_ports.remove_manager"] = b.remove_manager_module(error=failure)
        self.assertEqual(self.apply(), executor.EXIT_ACTION)
        self.assertIn("phase 6 stopped: a process uses the prefix", self.out)
        self.assertNotIn((7, "7.complete"), self.results())
        with open(self.run_dir.sub("report.md"), encoding="utf-8") as fh:
            self.assertIn("pid 77 runs", fh.read())


class ReportTest(ApplyTest):
    """`report.md` of a run"""

    def test_report_md_is_always_redacted(self):
        self.scenario_brew()
        edit = envclean.Edit(path="/Users/alice/.zprofile", kind="rc", old_text="a\n", new_text="b\n",
                             diff="--- /Users/alice/.zprofile\n+++ /Users/alice/.zprofile\n",
                             ops=["path entries, line 1: USER=alice"])
        self.modules["brew_ports.envclean"] = b.envclean_module([edit])
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        self.assertIn("/Users/alice/.zprofile", self.out)
        with open(self.run_dir.sub("report.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("~/.zprofile", text)
        self.assertIn("USER=<user>", text)
        self.assertNotIn("/Users/alice", text)
        self.assertTrue(text.startswith(f"# brew-ports apply {self.run_dir.run_id}"))
        self.assertIn("## phase 5: remove source packages", text)
        self.assertEqual(self.modules["brew_ports.envclean"].applied, [[edit]])


class CliTest(ApplyTest):
    """`apply` through `cli.main` and the real parser, with the test's runner"""

    def main(self, *argv):
        """Run `brew-ports` with the test's state directory, runner and stand-ins

        @param argv  the arguments after the program name
        @returns     the exit code, and the standard output followed by the standard error
        """
        out, err = io.StringIO(), io.StringIO()
        entry = {"apply": lambda ctx: executor.cmd_apply(ctx, make_runner=self.factory)}
        with mock.patch.dict(cli.COMMANDS, entry), mock.patch.dict(sys.modules, self.modules), \
                mock.patch("brew_ports.system.running_as_root", return_value=False), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--state-dir", self.sd.path] + list(argv), environ={"HOME": b.HOME, "USER": b.USER})
        return code, out.getvalue() + err.getvalue()

    def test_apply_plan_dry_run_and_stop_after(self):
        self.scenario_brew()
        code, text = self.main("apply", self.plan_path, "--dry-run", "--stop-after", "3")
        self.assertEqual(code, executor.EXIT_OK, text)
        self.assertIn("apply --dry-run stopped after phase 3 (--stop-after 3)", text)
        self.assertNotIn("== phase 4", text)
        code, text = self.main("apply", self.plan_path, "--yes", "--stop-after", "0")
        self.assertEqual(code, executor.EXIT_OK, text)
        code, text = self.main("apply", "--resume", self.runners[-1].run_dir.run_id, "--yes")
        self.assertEqual(code, executor.EXIT_OK, text)
        self.assertEqual(b.port_names(self.source.prefix), [])

    def test_resumed_dry_run_keeps_the_report(self):
        self.scenario_brew()
        self.assertEqual(self.apply(stop_after=1), executor.EXIT_OK)
        first = self.run_dir
        with open(first.sub("report.md"), encoding="utf-8") as fh:
            before = fh.read()
        self.assertEqual(self.apply(resume=first.run_id, dry_run=True), executor.EXIT_OK, self.out)
        with open(first.sub("report.md"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), before)


class HelperTest(unittest.TestCase):
    """The phase 6 prefixes, the phase order and the summary of phase 8"""

    def test_phase6_prefixes(self):
        plan = mock.Mock(options={"remove_manager": "/usr/local,/opt/local"}, path_removed={"/opt/local": []})
        self.assertEqual(exec_run.phase6_prefixes(plan), ["/usr/local", "/opt/local"])

    def test_phase_numbers_put_phase_0_first(self):
        plan = mock.Mock(phases=[model.Phase(8, "verify", [], False), model.Phase(3, "install", [], True)])
        self.assertEqual(executor.phase_numbers(plan), [0, 3, 8])

    def test_the_summary_lists_what_stays_with_the_user(self):
        plan = mock.Mock(kept=[make_package("tcl", "port", "/opt/local"), make_package("tk", "port", "/opt/local")],
                         left_in_place=[make_package("git", "formula", "/usr/local")], manual_casks=["virtualbox"],
                         target_upgrades=["openssl@3"], target_prefix="/opt/homebrew")
        self.assertEqual(executor.summary_lines(plan), [
            "still provided by /opt/local: tcl, tk",
            "left in place in /usr/local, which cannot be driven: git",
            "to run on a terminal after the migration (Homebrew calls sudo for it): `brew uninstall --cask virtualbox`",
            "upgraded in place in /opt/homebrew: openssl@3"])


if __name__ == "__main__":
    unittest.main()

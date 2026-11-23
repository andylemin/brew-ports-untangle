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

from brew_ports import (cli, doctor, envclean, exec_run, executor, model, plan_report, remove_manager, runner as r,
                        snapshot, state)
from brew_ports.homebrew import actions as brew_actions
from brew_ports.macports import actions as mp_actions
from brew_ports.model import Blocks, Severity
from tests.unit.fixtures.executor import builders as b
from tests.unit.fixtures.macports import builders as mb
from tests.unit.helpers import TempDirTest, make_instance, make_package


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
        # The temporary folder's length must not decide which commands are cut.
        width = mock.patch.object(plan_report, "COMMAND_WIDTH", 10_000)
        width.start()
        self.addCleanup(width.stop)

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
        lines = self.out.splitlines()
        self.assertEqual(lines[0], "Dry run: nothing will change.")
        self.assertEqual([line for line in lines if line.startswith("Phase ")], [
            "Phase 0  Checks before starting", "Phase 1  Save a record for undo", "Phase 3  Install the replacements",
            "Phase 4  Check the replacements", "Phase 5  Uninstall the old packages",
            "Phase 7  Clean up the shell files", "Phase 8  Final check"])
        for text in (f"  {self.target.binary} install --formula dnsmasq jq",
                     f"  sudo {self.source.binary} -N uninstall dnsmasq @2.90_0 jq @1.7.1_0 oniguruma @6.9.9_0",
                     "  Services to stop first: org.macports.dnsmasq   (each service file is deleted once its package "
                     "is gone)",
                     "  The run will need your password (sudo) to uninstall ports and stop a system service."):
            self.assertEqual(lines.count(text), 1, text)
        self.assertEqual(lines[-2:], ["Dry run finished: nothing was changed.",
                                      f"Next: brew-ports apply {self.plan_path}"])
        self.assertFalse([line for line in lines if line.startswith(("Run folder", "+ "))])
        self.assertEqual(b.port_names(self.source.prefix), ["dnsmasq", "jq", "oniguruma"])
        self.assertEqual(self.modules["brew_ports.verify"].calls, [])
        self.assertFalse(self.runners[-1].sudo_ready)
        self.assertNotIn(".complete", "".join(e.get("action_id", "") for e in self.run_dir.journal.entries()))

    def test_a_dry_run_cannot_be_resumed(self):
        self.scenario_brew()
        self.apply(dry_run=True)
        dry = self.run_dir.run_id
        self.assertEqual(self.apply(resume=dry), executor.EXIT_USAGE)
        self.assertEqual(self.out, f"brew-ports: run {dry} is a dry run, or no run of `brew-ports apply`: there is "
                                   "nothing to continue\n  Start one with: brew-ports apply PLAN\n")

    def test_the_shell_files_are_not_previewed_from_the_mac_as_it_is(self):
        self.scenario_brew()
        edit = envclean.Edit(path="/Users/alice/.zprofile", kind="rc", old_text="a\n", new_text="b\n",
                             diff="--- /Users/alice/.zprofile\n+++ /Users/alice/.zprofile\n", ops=["an edit"])
        self.modules["brew_ports.envclean"] = b.envclean_module([edit])
        self.assertEqual(self.apply(dry_run=True), executor.EXIT_OK, self.out)
        self.assertNotIn(".zprofile", self.out)
        self.assertNotIn("survives", self.out)
        self.assertEqual(self.modules["brew_ports.envclean"].bundles, [])
        self.assertIn("  Not shown in a dry run: what changes in your shell files depends on what phases 5 and 6 "
                      "leave.\n  The run shows each change before it makes any, and asks unless --yes is given.\n",
                      self.out)

    def test_a_long_command_is_cut_at_a_word(self):
        self.scenario_brew()
        with mock.patch.object(plan_report, "COMMAND_WIDTH", len(self.source.binary) + 30):
            self.assertEqual(self.apply(dry_run=True), executor.EXIT_OK, self.out)
        self.assertIn(f"  sudo {self.source.binary} -N uninstall dnsmasq ... (5 more words; --verbose shows all)\n",
                      self.out)


class StopAndResumeTest(ApplyTest):
    """`--stop-after`, interrupted installs and the rules that refuse or allow a resume"""

    def test_stop_after_then_resume_skips_passed_retry(self):
        self.scenario_ports()
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK, self.out)
        first = self.run_dir
        self.assertEqual(self.results().get((3, "3.complete")), "ok")
        self.assertNotIn((4, "4.complete"), self.results())
        self.assertTrue(self.out.endswith(f"\nStopped after phase 3 (--stop-after 3). Continue with: brew-ports apply "
                                          f"--resume {first.run_id}\n"), self.out)
        self.assertEqual(sorted(os.listdir(os.path.join(self.source.prefix, "Cellar"))), ["libidn2", "wget"])
        self.responder.log.clear()
        self.assertEqual(self.apply(resume=first.run_id), executor.EXIT_OK, self.out)
        self.assertEqual(self.run_dir.path, first.path)
        self.assertEqual(self.responder.ran("port", "install"), [])
        self.assertTrue(self.out.startswith(f"Continuing run {first.run_id} after phase 3.\nRun folder: "), self.out)
        self.assertNotIn("Phase 3 ", self.out)               # nothing is left of it, so it prints nothing
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
        self.assertTrue(self.out.endswith(
            "brew-ports: interrupted; a command that was running got the interrupt too, and the run waited for it to "
            f"end\n  Continue with: brew-ports apply --resume {first.run_id}\n"), self.out)
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
        brew = self.target.binary
        self.assertIn(f"  An earlier attempt of `{brew} install --formula dnsmasq jq` did not finish: what it may "
                      "have left half installed is installed again.\n"
                      f"  {brew} reinstall --formula jq oniguruma ... ok\n  {brew} install --formula dnsmasq ... ok\n",
                      self.out)

    def test_resume_refused_after_another_command(self):
        self.scenario_ports()
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK)
        first = self.run_dir.run_id
        self.sd.touch_dirty("20261113-120000-bbbbbb", "doctor --fix")
        later = os.stat(self.sd.dirty_path).st_mtime + 10
        os.utime(self.sd.dirty_path, (later, later))
        self.assertEqual(self.apply(resume=first), executor.EXIT_PREFLIGHT)
        self.assertEqual(self.out, f"brew-ports: `brew-ports doctor --fix` (run 20261113-120000-bbbbbb) changed this "
                                   f"Mac after run {first} started, so the run's plan may be out of date\n"
                                   "  Make a new plan with `brew-ports plan`, then apply that.\n")

    def test_an_unknown_run_is_a_usage_error(self):
        self.scenario_ports()
        self.assertEqual(self.apply(resume="20990101-000000-cccccc"), executor.EXIT_USAGE)


class RefusalTest(ApplyTest):
    """Plans that exit 3 before a run exists: a refused plan and one older than the dirty marker"""

    def test_a_refused_plan_file_exits_3(self):
        path = self.write_file("plan-refused.json", {"refused": {"exit": 1, "reasons": ["pinned jq"]}, "plan": None})
        self.plan_path = path
        self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertTrue(self.out.startswith("brew-ports: "), self.out)
        self.assertTrue(self.out.endswith(
            "plan-refused.json is not a plan: it holds the reasons why no plan was made\n"
            "    pinned jq\n  Settle them, then make a new plan with `brew-ports plan`.\n"), self.out)
        self.assertEqual(self.sd.run_ids(), [])

    def test_a_plan_older_than_the_marker_exits_3(self):
        self.scenario_ports()
        self.sd.touch_dirty("20261113-110000-dddddd", "rollback")
        old = os.stat(self.sd.dirty_path).st_mtime - 100
        os.utime(self.plan_path, (old, old))
        self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn("plan.json was made before `brew-ports rollback` (run 20261113-110000-dddddd) changed this Mac, "
                      "so it may be out of date\n  Make a new plan with `brew-ports plan`, then apply that.\n",
                      self.out)
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
                             remedies=[doctor.note(code, None, "Fix: repair it")], blocks=blocks)

    def test_blocking_finding_exits_3_first(self):
        self.scenario_brew()
        self.issues = [self.issue("ports-damaged-registry", self.source.prefix, (Blocks.UNINSTALL,))]
        self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn("\nPhase 0  Checks before starting\n"
                      "brew-ports: this stops the move: ports-damaged-registry title (MacPorts at "
                      f"{self.source.prefix})\n"
                      "    evidence\n    Fix: repair it\n", self.out)
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
        self.assertIn("this stops the move: ports-damaged-registry title", self.out)   # the identity deletes nothing
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
        self.assertIn("this stops the move: system-low-disk-space title", self.out)

    def test_undrivable_source_names_the_repair(self):
        self.scenario_brew()
        self.source.drivable = False
        self.source.usability = model.Usability.DAMAGED_REGISTRY
        self.issues = [self.issue("ports-damaged-registry", self.source.prefix, ())]
        self.issues[0].confirm_each = True
        self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn(f"brew-ports: MacPorts at {self.source.prefix}: its `port` command cannot run\n"
                      "  `brew-ports doctor --fix` can repair it; make a new plan with `brew-ports plan` afterwards.\n",
                      self.out)

    def test_a_refused_homebrew_target_exits_3(self):
        self.scenario_brew()
        self.host.catalogues[self.target.prefix].refusals["jq"] = {"date": "2026-11-01", "because": "unmaintained",
                                                                   "replacement_formula": "gojq"}
        self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn("brew-ports: Homebrew has disabled formula jq (since 2026-11-01: unmaintained), which the plan "
                      "installs\n  Make a new plan with `brew-ports plan`, then apply that. `--replace jq=gojq` takes "
                      "the one Homebrew names instead.\n", self.out)

    def test_sudo_that_caches_nothing_exits_3(self):
        self.scenario_brew()
        with mock.patch.object(r.FakeRunner, "sudo_preflight", side_effect=r.PreflightError("no ticket")):
            self.assertEqual(self.apply(), executor.EXIT_PREFLIGHT)
        self.assertIn("no ticket", self.out)
        self.assertFalse(os.path.exists(self.sd.dirty_path))


class NotesOnceTest(ApplyTest):
    """A note of the final check is given once, not after the check of the replacements as well"""

    def test_a_note_of_both_checks_prints_once(self):
        self.scenario_brew()
        real = self.modules["brew_ports.verify"].check

        def noted(*args, **kw):
            result = real(*args, **kw)
            result.report("language-packages", "gems.txt", "kept in the run folder")
            return result
        self.modules["brew_ports.verify"].check = noted
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        self.assertEqual(self.modules["brew_ports.verify"].calls, [True, False])
        self.assertEqual(self.out.count("kept in the run folder"), 1)
        self.assertIn("\nPhase 4  Check the replacements\n  Passed: every replacement is installed, provides commands "
                      "and finds its libraries.\n", self.out)
        self.assertIn("\nPhase 8  Final check\n  Passed: the replacements are in place, and what the plan uninstalls "
                      "is gone.\n  note gems.txt (language packages): kept in the run folder\n", self.out)


class GateTest(ApplyTest):
    """Phase 4: a failed gate stops the run before any removal"""

    def test_a_failed_gate_exits_4_and_removes_nothing(self):
        self.scenario_brew()
        self.modules["brew_ports.verify"] = b.verify_module({True: [("installed", "jq -> jq", "jq is not installed")]})
        self.assertEqual(self.apply(), executor.EXIT_ACTION)
        run_id = self.run_dir.run_id
        self.assertTrue(self.out.endswith(
            "\nPhase 4  Check the replacements\n"
            "  jq -> jq (replacements installed): jq is not installed\n"
            "brew-ports: the check of the replacements failed, so no old package was uninstalled\n"
            f"  Fix what the lines above name, then continue with: brew-ports apply --resume {run_id}\n"
            "  Or leave those packages where they are: make the plan again with `--leave jq` added.\n"), self.out)
        self.assertEqual(self.responder.ran("port", "uninstall"), [])
        self.assertEqual(b.port_names(self.source.prefix), ["dnsmasq", "jq", "oniguruma"])
        self.assertFalse([k for k in self.results() if k[0] == 5])


class UpgradeAllTest(ApplyTest):
    """A plan made with `--upgrade-all`: phase 3 names the upgrades it adds, and a break among them is a task"""

    TASK = ("Install pkgconf again, because its upgrade, which --upgrade-all asked for, left it uninstalled in "
            "Homebrew at /opt/homebrew: brew install --formula pkgconf")
    GATE = ("gate", "pkgconf", "is uninstalled in Homebrew at /opt/homebrew after its upgrade", TASK)
    PASSED = "  Passed: every replacement is installed, provides commands and finds its libraries.\n"

    def scenario(self, *more):
        """Plan the move of scenario A with the upgrades of pkgconf and of the app firefox, which no replacement needs

        The target's app docker-desktop has a newer version that the plan leaves.

        @param more  further formulae that the plan upgrades with pkgconf
        """
        self.scenario_brew()
        names = ["pkgconf", *more]
        others = brew_actions.upgrade_formulae(self.target, "arm64", "3.upgrade.others", names)
        apps = brew_actions.upgrade_casks(self.target, "arm64", "3.upgrade.casks", ["firefox"])
        self.host.packages.append(make_package("docker-desktop", "cask", self.target.prefix, outdated=True))
        self.save_plan(b.plan(self.target, [self.source], mappings=self.mappings, removal=self.removal,
                              phase3=[others, apps, self.install], optional=names, optional_casks=["firefox"],
                              upgrade_all=True))

    def upgrades(self):
        """Return the `brew upgrade` and `brew reinstall` commands of formulae that the last command ran

        @returns  each command from its verb on, in order
        """
        return [tail[1:] for tail in self.responder.ran("brew")
                if tail[1] in ("upgrade", "reinstall") and "--cask" not in tail]

    def test_phase_3_asks_for_the_upgrades_and_says_what_follows(self):
        self.scenario()
        self.assertEqual(self.apply(yes=False, tty=True, answers=[True, True]), executor.EXIT_OK, self.out)
        self.assertEqual(self.ctx.asked[0], "Install the replacements and upgrade the other packages?")
        brew = self.target.binary
        self.assertIn("\nPhase 3  Install the replacements and upgrade the other packages\n"
                      f"  {brew} upgrade --formula pkgconf\n  {brew} upgrade --cask firefox\n"
                      f"  {brew} install --formula dnsmasq jq\n"
                      "  Then every package that uses an upgraded one is checked; one that lost a library is "
                      "installed again.\n"
                      "  Homebrew may close an app that is open for its upgrade, and then opens it again.\n"
                      "  n stops the run here; ", self.out)
        self.assertEqual([tail[1:] for tail in self.responder.ran("brew", "upgrade")],
                         [["upgrade", "--formula", "pkgconf"], ["upgrade", "--cask", "firefox"]])

    def test_the_closing_lines_count_what_is_still_to_upgrade(self):
        self.scenario()
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        self.assertIn(f"\n1 package of Homebrew at {self.target.prefix} still has a newer version, because the plan "
                      "left it as it is or its upgrade failed: docker-desktop.\n"
                      f"To upgrade it: {self.target.binary} upgrade\nNext: open a new Terminal window", self.out)

    def test_a_package_that_an_added_upgrade_broke_is_a_task(self):
        self.scenario()
        self.modules["brew_ports.verify"] = b.verify_module(tasks={True: [self.GATE]})
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        self.assertIn(f"\nPhase 4  Check the replacements\n{self.PASSED}  For you to do after the run: {self.TASK}\n",
                      self.out)
        self.assertEqual(len(self.responder.ran("port", "uninstall")), 1)       # the move went on
        self.assertIn(f"\nFor you to do:\n  {self.TASK}\nUndo: brew-ports rollback", self.out)

    def test_a_package_has_one_task_in_the_words_of_the_last_check(self):
        self.scenario()
        text = "bin/pkgconf references libgone.dylib, which does not exist"
        again = "Install pkgconf again, because its upgrade left it without a library it needs: "
        # Phase 6 uninstalled the Homebrew that came first on PATH, so by phase 8 the command is typed as `brew`.
        early, late = again + "/opt/homebrew/bin/brew reinstall --formula pkgconf", again + "brew reinstall pkgconf"
        self.modules["brew_ports.verify"] = b.verify_module(tasks={True: [("linkage", "pkgconf", text, early)],
                                                                   False: [("linkage", "pkgconf", text, late)]})
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        self.assertIn(f"  note pkgconf (clean linkage): {text} (for you to repair; the move does not need it)\n",
                      self.out)
        closing = self.out[self.out.index("\nFor you to do:\n"):]
        self.assertEqual((closing.count(late), closing.count("Install pkgconf again")), (1, 1))

    def test_a_failed_check_lists_the_task_once(self):
        self.scenario()
        self.modules["brew_ports.verify"] = b.verify_module({True: [("installed", "jq -> jq", "jq is not installed")]},
                                                            tasks={True: [self.GATE]})
        self.assertEqual(self.apply(), executor.EXIT_ACTION, self.out)
        self.assertNotIn("For you to do after the run", self.out)
        self.assertEqual(self.out.count(self.TASK), 1)
        self.assertIn(f"\nFor you to do:\n  {self.TASK}\n", self.out)

    def test_each_start_of_a_run_finds_its_tasks_again(self):
        self.scenario()
        self.modules["brew_ports.verify"] = b.verify_module(tasks={True: [self.GATE]})
        self.assertEqual(self.apply(stop_after=4), executor.EXIT_OK, self.out)
        self.assertTrue(self.out.endswith(f"For you to do:\n  {self.TASK}\n"), self.out)
        first = self.run_dir.run_id
        self.assertEqual(self.apply(resume=first, stop_after=5), executor.EXIT_OK, self.out)
        self.assertTrue(self.out.endswith(f"For you to do:\n  {self.TASK}\n"), self.out)
        # Once the package is repaired, the next start has no such task.
        self.modules["brew_ports.verify"] = b.verify_module()
        self.assertEqual(self.apply(resume=first), executor.EXIT_OK, self.out)
        self.assertNotIn("Install pkgconf again", self.out)

    def test_an_upgrade_that_failed_runs_again_as_it_is(self):
        self.scenario("ddrescue")
        self.responder.fail = {"ddrescue": 1}
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK, self.out)
        self.assertEqual(self.results()[(3, "3.upgrade.others")], "failed")
        self.responder.log.clear()
        self.assertEqual(self.apply(resume=self.run_dir.run_id, stop_after=3), executor.EXIT_OK, self.out)
        # The attempt ran to its end, so nothing is half installed: pkgconf is not installed a second time.
        self.assertEqual(self.upgrades(), [["upgrade", "--formula", "pkgconf", "ddrescue"],
                                           ["upgrade", "--formula", "pkgconf"], ["upgrade", "--formula", "ddrescue"]])
        self.assertNotIn("did not finish", self.out)

    def test_an_upgrade_that_was_cut_short_resumes_as_a_reinstall(self):
        self.scenario("ddrescue")

        def killed(tail):
            if "--formula" in tail and "pkgconf" in tail:
                self.responder.answer_brew([tail[0], "upgrade", "--formula", "pkgconf"], "upgrade")
                self.runners[-1].note_sigint()
                return r.FakeResponse(exit=130)
            return None
        self.responder.hooks["upgrade"] = killed
        self.assertEqual(self.apply(), executor.EXIT_ACTION, self.out)
        self.assertNotIn((3, "3.upgrade.others"), self.results())
        del self.responder.hooks["upgrade"]
        self.responder.log.clear()
        self.assertEqual(self.apply(resume=self.run_dir.run_id, stop_after=3), executor.EXIT_OK, self.out)
        self.assertEqual(self.upgrades(), [["reinstall", "--formula", "pkgconf"],
                                           ["upgrade", "--formula", "ddrescue"]])

    def test_a_failed_install_does_not_install_the_upgrades_again(self):
        self.scenario("ddrescue")
        self.responder.fail = {"jq": 1}
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK, self.out)
        self.assertEqual(self.results()[(3, "3.install.bottled")], "failed")
        self.responder.log.clear()
        self.assertEqual(self.apply(resume=self.run_dir.run_id, stop_after=3), executor.EXIT_OK, self.out)
        # Only the install that failed runs again, as planned: what the other commands upgraded is left alone.
        ran = [tail[1:] for tail in self.responder.ran("brew") if tail[1] in ("install", "upgrade", "reinstall")]
        self.assertEqual(ran, [["install", "--formula", "dnsmasq", "jq"], ["install", "--formula", "dnsmasq"],
                               ["install", "--formula", "jq"]])
        self.assertNotIn("did not finish", self.out)

    def test_an_attempt_cut_short_after_a_failed_one_is_seen(self):
        self.scenario("ddrescue")
        self.responder.fail = {"ddrescue": 1}
        self.assertEqual(self.apply(stop_after=3), executor.EXIT_OK, self.out)
        first = self.run_dir.run_id
        self.responder.fail = {}

        def killed(tail):
            if "--formula" in tail and "pkgconf" in tail:
                self.runners[-1].note_sigint()
                return r.FakeResponse(exit=130)
            return None
        self.responder.hooks["upgrade"] = killed
        self.assertEqual(self.apply(resume=first), executor.EXIT_ACTION, self.out)
        del self.responder.hooks["upgrade"]
        self.responder.log.clear()
        self.assertEqual(self.apply(resume=first, stop_after=3), executor.EXIT_OK, self.out)
        # The result of the first attempt does not hide the second: it is resumed against its own listing, in
        # which pkgconf was upgraded already, so nothing is installed a second time.
        self.assertIn("did not finish", self.out)
        self.assertEqual(self.upgrades(), [["upgrade", "--formula", "pkgconf", "ddrescue"]])


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
        self.assertTrue(self.out.endswith(
            "  Started the service org.macports.dnsmasq again.\n"
            "brew-ports: interrupted; a command that was running got the interrupt too, and the run waited for it to "
            f"end\n  Continue with: brew-ports apply --resume {self.run_dir.run_id}\n"), self.out)
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

    def test_no_terminal_and_no_yes_stops_before_the_first_change(self):
        self.scenario_brew()
        self.assertEqual(self.apply(yes=False), executor.EXIT_ACTION)
        run_id = self.run_dir.run_id
        self.assertTrue(self.out.endswith(
            "brew-ports: phase 3 asks before it changes anything, and there is no terminal to ask on\n"
            f"  Run it in a Terminal window, or answer yes to every question: brew-ports apply --resume {run_id} "
            "--yes\n"), self.out)
        self.assertIn(f"  {self.target.binary} install --formula dnsmasq jq\n", self.out)   # what it would have run
        self.assertFalse(os.path.exists(self.sd.dirty_path))
        self.assertEqual(self.responder.ran("brew", "install"), [])
        self.assertTrue(snapshot.is_complete(self.run_dir))    # the record for undo asks nothing

    def test_a_no_on_a_terminal_stops_before_its_phase(self):
        self.scenario_brew()
        self.assertEqual(self.apply(yes=False, tty=True, answers=[True, False]), executor.EXIT_ACTION)
        self.assertEqual(self.ctx.asked, ["Install the replacements?", "Uninstall the old packages?"])
        run_id = self.run_dir.run_id
        port = f"  sudo {self.source.binary} -N uninstall dnsmasq @2.90_0 jq @1.7.1_0 oniguruma @6.9.9_0\n"
        self.assertTrue(self.out.endswith(
            port + f"  n stops the run here; `brew-ports apply --resume {run_id}` continues it.\n"
            f"Stopped before phase 5, as you answered. Continue with: brew-ports apply --resume {run_id}\n"), self.out)
        self.assertNotIn("brew-ports: ", self.out)             # the user's own answer is no error
        self.assertEqual(len(self.responder.ran("brew", "install")), 1)
        self.assertEqual(self.responder.ran("port", "uninstall"), [])

    def test_a_question_shows_its_commands_and_then_their_results(self):
        self.scenario_brew()
        self.assertEqual(self.apply(yes=False, tty=True, answers=[True, True]), executor.EXIT_OK, self.out)
        brew = f"  {self.target.binary} install --formula dnsmasq jq"
        self.assertIn(f"\nPhase 3  Install the replacements\n{brew}\n  n stops the run here; `brew-ports apply "
                      f"--resume {self.run_dir.run_id}` continues it.\n{brew} ... ok\n", self.out)
        with open(self.run_dir.sub("report.md"), encoding="utf-8") as fh:
            self.assertIn("\nInstall the replacements? (y/n) [n] y\n", fh.read())

    def test_yes_prints_each_command_once_with_its_result(self):
        self.scenario_brew()
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        self.assertEqual(self.out.count("install --formula dnsmasq jq"), 1)
        self.assertEqual(self.out.count(" -N uninstall dnsmasq"), 1)
        self.assertNotIn("+ ", self.out)                       # the escalated commands are not echoed as well
        self.assertNotIn("n stops the run here", self.out)


class HandTasksTest(ApplyTest):
    """What is left for the user to do is said whenever a run ends, also when it ends early"""

    def hand_edit(self):
        """Have phase 7 find a shell file that only the user can edit

        @returns  the task's line in the closing lines
        """
        edit = envclean.Edit(path="/Users/alice/.bash_profile", kind="rc", old_text="a\n", new_text="b\n", diff="",
                             manual="it belongs to root")
        self.modules["brew_ports.envclean"] = b.envclean_module([edit])
        return "  Make the change phase 7 showed for ~/.bash_profile, which brew-ports does not edit.\n"

    def test_a_failed_final_check_keeps_the_tasks_and_the_undo(self):
        self.scenario_brew()
        task = self.hand_edit()
        self.modules["brew_ports.verify"] = b.verify_module({False: [("removed", "jq", "jq is still installed")]})
        self.assertEqual(self.apply(), executor.EXIT_VERIFY, self.out)
        self.assertIn("\n  jq (sources removed): jq is still installed\nFor you to do:\n" + task
                      + f"Undo: brew-ports rollback {self.run_dir.run_id}   (puts back", self.out)
        self.assertIn("brew-ports: the final check found 1 failure, listed above\n", self.out)

    def test_stop_after_gives_the_tasks_gathered_so_far(self):
        self.scenario_brew()
        task = self.hand_edit()
        self.assertEqual(self.apply(stop_after=7), executor.EXIT_OK, self.out)
        self.assertTrue(self.out.endswith("For you to do:\n" + task), self.out)

    def test_a_dry_run_names_the_app_only_the_user_can_uninstall(self):
        self.scenario_ports()
        self.plan.manual_casks = ["iterm2"]
        self.save_plan(self.plan)
        self.assertEqual(self.apply(dry_run=True), executor.EXIT_OK, self.out)
        self.assertIn("\nFor you to do after the run:\n  Uninstall the app iterm2 yourself, because Homebrew asks for "
                      f"your password: {self.source.binary} uninstall --cask iterm2\nNext: brew-ports apply ", self.out)


class RecordTest(ApplyTest):
    """Phase 1: what it says about the record it saves for undo"""

    def test_it_says_how_much_was_not_saved_and_where_that_is_named(self):
        self.scenario_brew()
        self.responder.hooks["tmutil"] = lambda tail: r.FakeResponse(exit=1, stderr="no snapshot\n")
        self.assertEqual(self.apply(stop_after=1), executor.EXIT_OK, self.out)
        with open(os.path.join(snapshot.snapshot_dir(self.run_dir), snapshot.NOTES), encoding="utf-8") as fh:
            notes = {line.strip() for line in fh if line.strip()}
        self.assertEqual(len(notes), 2, notes)                 # the disk snapshot, and one part of the record
        self.assertIn("  Saved what is installed, your shell files and your service files in the run folder, for "
                      "`brew-ports rollback`.\n  1 part of that record could not be saved: snapshot/notes.txt in the "
                      "run folder names it.\n  macOS could not take a local snapshot of the disk. `brew-ports "
                      "rollback` does not need one.\n", self.out)
        self.assertNotIn("macOS also took", self.out)

    def test_saving_the_record_leaves_the_plan_good(self):
        self.scenario_brew()
        self.source.features = tuple(self.source.features or ()) + ("snapshot",)
        self.assertEqual(self.apply(yes=False, tty=True, answers=[False]), executor.EXIT_ACTION, self.out)
        self.assertEqual(len(self.responder.ran("port", "snapshot")), 1)
        self.assertFalse(os.path.exists(self.sd.dirty_path))   # a no at the first question changed nothing
        self.assertEqual(self.apply(dry_run=True), executor.EXIT_OK, self.out)

    def test_it_says_that_macos_took_a_snapshot_of_the_disk(self):
        self.scenario_brew()
        self.assertEqual(self.apply(stop_after=1), executor.EXIT_OK, self.out)
        self.assertIn("  macOS also took a local snapshot of the disk, which it keeps for about a day or until it "
                      "needs the space.\n", self.out)
        self.assertEqual(self.ctx.asked, [])                   # saving the record asks nothing


class PhaseSixTest(ApplyTest):
    """Phase 6 through the stand-in for `remove_manager`"""

    def plan_with_phase6(self):
        """Plan the move of scenario A, which uninstalls its MacPorts source afterwards"""
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
        self.assertNotIn("This list is from the plan", self.out)   # nothing is asked, so no preview either
        with open(self.run_dir.sub("report.md"), encoding="utf-8") as fh:
            self.assertIn("phase 6 done", fh.read())
        self.assertEqual(self.results().get((6, "6.complete")), "ok")
        # Phase 7 weighs a scan taken after phase 6: an undrivable source's packages go only then.
        survivors_bundle, = self.modules["brew_ports.envclean"].bundles
        self.assertIsNot(survivors_bundle, call["bundle"])
        self.assertEqual(self.host.scans, 5)                 # phases 0, 4, 6, 7 and 8

    def test_the_preview_of_phase_6_is_shown_as_the_plans_own(self):
        self.scenario_brew()
        prefix = self.source.prefix
        steps = [model.Action(action_id="6.archive.x", kind="command", sudo=True, description="save", manual=True,
                              argv=["/usr/bin/tar", "-czf", "-", "-C", "/", prefix.lstrip("/") + "/etc"],
                              instance_prefix=prefix),
                 model.Action(action_id="6.delete.y", kind="command", argv=["/bin/rm", "-rf", prefix], sudo=True,
                              description="delete", manual=True, instance_prefix=prefix)]
        self.save_plan(b.plan(self.target, [self.source], mappings=self.mappings, removal=self.removal,
                              phase3=[self.install], phase6=steps, remove=[prefix]))
        preview = (f"\nPhase 6  Uninstall MacPorts at {prefix}\n  Save in the run folder: {prefix}/etc\n"
                   f"  Then delete: {prefix}\n  This list is from the plan. It is made again when the phase runs: "
                   "what is gone by then is skipped.\n")
        self.assertEqual(self.apply(dry_run=True), executor.EXIT_OK, self.out)
        self.assertIn(preview, self.out)
        self.assertEqual(self.apply(yes=False, tty=True, answers=[True, True, True]), executor.EXIT_OK, self.out)
        self.assertIn(preview + "  To undo this later, reinstall it first; `brew-ports rollback` then puts its "
                      "packages back.\n", self.out)
        self.assertEqual(len(self.modules["brew_ports.remove_manager"].calls), 1)

    def test_a_no_leaves_the_manager_installed_and_the_run_goes_on(self):
        self.plan_with_phase6()
        code = self.apply(yes=False, tty=True, answers=[True, True, False])
        self.assertEqual(code, executor.EXIT_OK, self.out)
        where = f"MacPorts at {self.source.prefix}"
        self.assertEqual(self.ctx.asked[2:], [f"Uninstall {where}?"])
        self.assertIn(f"\nPhase 6  Uninstall {where}\n"
                      "  To undo this later, reinstall it first; `brew-ports rollback` then puts its packages back.\n"
                      "  What is saved stays in the run folder, for you to copy back.\n"
                      f"  n leaves {where} installed, without its packages, and the run goes on.\n"
                      f"  {where} stays installed, as you answered; a new plan can uninstall it later.\n", self.out)
        self.assertIn(f"\nFinished: 2 packages moved into Homebrew at {self.target.prefix}; 3 ports uninstalled from "
                      f"{where}.\n", self.out)
        self.assertEqual(self.modules["brew_ports.remove_manager"].calls, [])
        self.assertEqual([e["prefixes"] for e in self.entry(executor.DECLINED)], [[self.source.prefix]])
        results = self.results()
        self.assertEqual([results.get((n, f"{n}.complete")) for n in (6, 7, 8)], ["ok", "ok", "ok"])

    def test_a_no_to_one_deleted_whole_leaves_its_packages(self):
        self.plan_with_phase6()
        self.plan.path_removed = {self.source.prefix: [("port", "jq")]}
        self.save_plan(self.plan)
        self.assertEqual(self.apply(yes=False, tty=True, answers=[True, True, False]), executor.EXIT_OK, self.out)
        self.assertIn(f"  n leaves MacPorts at {self.source.prefix} installed, with what is still in it, and the run "
                      "goes on.\n", self.out)

    def test_a_resume_after_a_no_does_not_ask_again(self):
        self.plan_with_phase6()
        code = self.apply(yes=False, tty=True, answers=[True, True, False], stop_after=6)
        self.assertEqual(code, executor.EXIT_OK, self.out)
        # A finding that stops the uninstall of a manager is beside the point for one that stays.
        self.issues = [doctor._issue("ports-damaged-registry", Severity.HIGH, "title", None, self.source.prefix,
                                     evidence=[], remedies=[], blocks=(Blocks.REMOVE,))]
        code = self.apply(resume=self.run_dir.run_id, yes=False, tty=True, answers=[True])
        self.assertEqual(code, executor.EXIT_OK, self.out)
        self.assertEqual(self.ctx.asked, ["Uninstall the old packages?"])
        self.assertIn(f"  MacPorts at {self.source.prefix} stays installed, as you answered.\n", self.out)
        self.assertEqual(self.modules["brew_ports.remove_manager"].calls, [])

    def test_no_terminal_and_no_yes_still_stops_at_phase_6(self):
        self.scenario_brew()
        note = model.Action(action_id=f"6.note.{state.slug(self.source.prefix)}.checks", kind="note", argv=[],
                            sudo=False, description="the checks", manual=True)
        self.host.services = []
        self.save_plan(b.plan(self.target, [self.source], phase6=[note], remove=[self.source.prefix]))
        self.assertEqual(self.apply(stop_after=1), executor.EXIT_OK, self.out)
        self.assertEqual(self.apply(resume=self.run_dir.run_id, yes=False), executor.EXIT_ACTION)
        self.assertIn("brew-ports: phase 6 asks before it changes anything, and there is no terminal to ask on\n",
                      self.out)
        self.assertEqual(self.entry(executor.DECLINED), [])
        self.assertEqual(self.modules["brew_ports.remove_manager"].calls, [])

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
        self.assertTrue(self.out.endswith(f"\nPhase 6  Uninstall MacPorts at {self.source.prefix}\n"
                                          "brew-ports: a process uses the prefix\n"
                                          f"  Continue with: brew-ports apply --resume {self.run_dir.run_id}\n"),
                        self.out)
        self.assertEqual(self.out.count("a process uses the prefix"), 1)
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
        self.assertIn("\n## Phase 5  Uninstall the old packages\n", text)
        self.assertIn("  Edited ~/.zprofile; the file as it was is kept in the run folder.\n", text)
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
        self.assertTrue(text.endswith("\nDry run stopped after phase 3 (--stop-after 3): nothing was changed.\n"), text)
        self.assertNotIn("Phase 4 ", text)
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

    def test_the_summary_lists_what_stays_and_the_hand_tasks(self):
        plan = mock.Mock(kept=[make_package("tcl", "port", "/opt/local"), make_package("tk", "port", "/opt/local")],
                         left_in_place=[make_package("git", "formula", "/usr/local")], manual_casks=["virtualbox"],
                         source_prefixes=["/opt/local", "/usr/local"])
        known = {"/opt/local": make_instance(model.Manager.PORTS, "/opt/local"),
                 "/usr/local": make_instance(model.Manager.BREW, "/usr/local", binary="/usr/local/bin/brew")}
        run = mock.Mock(plan=plan, todo=[], instance=known.get, fresh_prefix=str, bundle=None)
        self.assertEqual(executor.summary_lines(run), [
            "2 packages stay in MacPorts at /opt/local: tcl, tk",
            "1 package stays in Homebrew at /usr/local, whose `brew` command cannot run: git"])
        self.assertEqual(run.todo, ["Uninstall the app virtualbox yourself, because Homebrew asks for your password: "
                                    "brew uninstall --cask virtualbox"])
        # With the scan at hand the command names the Homebrew that holds the app, which plain `brew` may not be.
        run.todo.clear()
        run.bundle = mock.Mock(result=mock.Mock(packages=[make_package("virtualbox", "cask", "/usr/local")]))
        executor.summary_lines(run)
        self.assertEqual(run.todo, ["Uninstall the app virtualbox yourself, because Homebrew asks for your password: "
                                    "/usr/local/bin/brew uninstall --cask virtualbox"])

    @staticmethod
    def finished_run(target, packages, last=8, homebrew=False):
        """Return a run that has finished, as far as the count of newer versions reads it

        @param target    the target installation
        @param packages  the packages of the run's last scan
        @param last      the plan's last phase
        @param homebrew  whether the run's last scan finds a Homebrew
        @returns         the run
        """
        plan = mock.Mock(phases=[model.Phase(3, "install", [], True), model.Phase(last, "last", [], False)])
        return mock.Mock(plan=plan, target=target, bundle=mock.Mock(result=mock.Mock(packages=packages)),
                         runner=mock.Mock(host_arch="arm64"), homebrew_present=homebrew)

    def test_what_still_has_a_newer_version_is_counted_after_the_run(self):
        brew = make_instance(model.Manager.BREW, "/opt/homebrew", binary="/opt/homebrew/bin/brew", arch="arm64")
        packages = [make_package("jq", "formula", "/opt/homebrew", outdated=True),
                    make_package("firefox", "cask", "/opt/homebrew", outdated=True),
                    make_package("wget", "formula", "/opt/homebrew"),
                    make_package("node", "formula", "/opt/homebrew", outdated=True, pinned=True),
                    make_package("curl", "port", "/opt/local", outdated=True)]
        # Named: what `brew upgrade` upgrades in the target. A pinned formula and another installation are not;
        # the pin is told apart, as that command upgrades what the pinned formula uses.
        self.assertEqual(executor.newer(self.finished_run(brew, packages)),
                         (["jq", "firefox"], "/opt/homebrew/bin/brew upgrade", True))
        # A run without phase 8 took no count, and a count of nothing is not said.
        self.assertIsNone(executor.newer(self.finished_run(brew, packages, last=5)))
        self.assertIsNone(executor.newer(self.finished_run(brew, packages[2:3])))

    def test_the_upgrade_command_is_the_one_that_works_when_copied(self):
        intel = make_instance(model.Manager.BREW, "/usr/local", binary="/usr/local/bin/brew", arch="x86_64")
        outdated = [make_package("jq", "formula", "/usr/local", outdated=True)]
        self.assertEqual(executor.newer(self.finished_run(intel, outdated)),
                         (["jq"], "arch -x86_64 /usr/local/bin/brew upgrade", False))
        ports = make_instance(model.Manager.PORTS, "/opt/local", binary="/opt/local/bin/port")
        rows = [make_package("curl", "port", "/opt/local", outdated=True),
                make_package("curl", "port", "/opt/local", outdated=True, active=False)]
        self.assertEqual(executor.newer(self.finished_run(ports, rows)),
                         (["curl"], "sudo /opt/local/bin/port upgrade outdated", False))
        # While a Homebrew is installed, MacPorts builds in trace mode, as the run's own builds do.
        self.assertEqual(executor.newer(self.finished_run(ports, rows, homebrew=True)),
                         (["curl"], "sudo /opt/local/bin/port -t upgrade outdated", False))


if __name__ == "__main__":
    unittest.main()

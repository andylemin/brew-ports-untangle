"""The state of one start of an `apply` run, shared by the phase modules

The journal is read as it stood when the start began, so the resume rule weighs earlier starts only.
"""

from __future__ import annotations

import importlib
import json
import os
from collections.abc import Sequence
from typing import Any

from . import doctor, model, report, scan, state, system
from .context import Context
from .model import Action, Instance, Manager, Phase, Plan, is_recorded_as
from .plan_phases import PHASE_NAMES
from .runner import ActionFailed, EscalationFailed, Interrupted, RootFiles

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_ACTION = 4
EXIT_VERIFY = 5

PLAN_FILE = "plan.json"
REPORT_FILE = "report.md"
SOURCE_BIN = "source-bin.json"
COMPLETE = "%d.complete"
START = "0.apply"


class Stop(Exception):
    """The run ends with `code` once `lines` are printed"""

    def __init__(self, code: int, lines: Sequence[str]) -> None:
        """Stop the run

        @param code   the exit code
        @param lines  why the run stops, printed before it ends
        """
        super().__init__("; ".join(lines))
        self.code = code
        self.lines = list(lines)


def phase6_prefixes(plan: Plan) -> list[str]:
    """Return the source prefixes phase 6 removes: those of the `remove_manager` option, then `path_removed`

    @param plan  the plan
    @returns     the prefixes, each once
    """
    named = plan.options.get("remove_manager", "").split(",")
    return [prefix for prefix in dict.fromkeys(named + sorted(plan.path_removed)) if prefix]


def module(name: str) -> Any:
    """Return the `brew_ports` module of that name, imported when a phase needs it

    @param name  the module's name inside the package, such as `verify`
    @returns     the module, from `sys.modules` once imported
    """
    return importlib.import_module("brew_ports." + name)


class Run:
    """One start of an `apply` run"""

    def __init__(self, ctx: Context, runner, run_dir: state.RunDir, plan: Plan, plan_path: str, *, resumed: bool,
                 dry_run: bool, stop_after: int | None) -> None:
        """Begin a start: read the journal as it stands, and hook the runner unless the start is a dry run

        @param ctx         the command's context
        @param runner      the runner of the run
        @param run_dir     the run directory
        @param plan        the run's plan
        @param plan_path   the plan file, for the report
        @param resumed     whether the start is `--resume`
        @param dry_run     whether the start is `--dry-run`
        @param stop_after  the last phase to run, or None for every phase
        """
        self.ctx: Context = ctx
        self.runner = runner
        self.run_dir = run_dir
        self.plan = plan
        self.plan_path = plan_path
        self.resumed = resumed
        self.dry_run = dry_run
        self.stop_after = stop_after
        self.environ = runner.environ
        self.home = self.environ.get("HOME") or os.path.expanduser("~")
        self.lines: list[str] = []
        self.touched = False
        self.bundle: Any = None              # the newest fresh scan
        self.bundles: list[Any] = []
        self.instances: list[Instance] = list(plan.instances)
        self.fresh: list[Instance] = []
        self.issues: list[model.Issue] = []
        self.rebuilt: set[str] = set()       # phase 3 rebuilds run in this start
        self._root_files: RootFiles | None = None
        self.entries = run_dir.journal.entries()
        self.results: dict[tuple[Any, str], str] = {}
        self.listings: dict[str, dict[str, Any]] = {}
        for entry in self.entries:
            action_id = str(entry.get("action_id") or "")
            if "result" in entry:
                self.results[(entry.get("phase"), action_id)] = entry["result"]
            if entry.get("kind") == "listing" and entry.get("of"):
                self.listings.setdefault(str(entry["of"]), entry)
        if not dry_run:
            self._hook()

    # The journal and the marker --------------------------------------------------------------

    def _hook(self) -> None:
        """Wrap `runner.run` so the dirty marker is rewritten just before the first action that changes the host

        Read-only probes, such as the scans and the gate, never touch it.
        """
        original = self.runner.run

        def run(action: Action, defer_result: bool = False):
            if not action.read_only:
                self.touch()
            return original(action, defer_result=defer_result)
        self.runner.run = run

    def touch(self) -> None:
        """Rewrite the dirty marker once per start, before the start's first change to the host"""
        if not self.touched and not self.dry_run:
            self.ctx.state.touch_dirty(self.run_dir.run_id, "apply")
            self.touched = True

    def ok(self, phase: int, action_id: str) -> bool:
        """Return whether the action's result line was `ok` when this start began: the resume rule

        @param phase      the phase number
        @param action_id  the action's id
        @returns          True only for a recorded `ok`
        """
        return self.results.get((phase, action_id)) == "ok"

    def completed(self, phase: int) -> bool:
        """Return whether an earlier start journaled the phase's `<n>.complete` line

        @param phase  the phase number
        @returns      True when an earlier start journaled the line with `ok`
        """
        return self.ok(phase, COMPLETE % phase)

    def past(self, phase: int) -> bool:
        """Return whether the run had finished `phase` before this start

        Its `<n>.complete` line or a journal entry of a later phase says so.

        @param phase  the phase number
        @returns      True when an earlier start finished the phase
        """
        if self.completed(phase):
            return True
        return any(isinstance(e.get("phase"), int) and e["phase"] > phase for e in self.entries)

    def journal(self, record: dict[str, Any]) -> None:
        """Append a record to the run's journal, stamped with the time and the runner's phase; a dry run writes none

        @param record  the entry's fields, which override the stamp
        """
        if self.dry_run:
            return
        entry: dict[str, Any] = {"ts": state.now_iso(), "phase": self.runner.phase}
        entry.update(record)
        self.run_dir.journal.append(entry)

    def complete(self, phase: int) -> None:
        """Journal the phase's `<n>.complete` line, the `ok` result that `past` reads in a later start

        @param phase  the phase number
        """
        self.journal({"phase": phase, "action_id": COMPLETE % phase, "result": "ok"})

    def phase6_begun(self, prefix: str) -> bool:
        """Return whether phase 6 has begun deleting the instance in this run, by `remove_manager`'s rule

        Its findings then block nothing, and its recorded identity stands in for the deleted prefix.

        @param prefix  the instance's prefix
        @returns       True once a deletion of the instance has run
        """
        entries = [e for e in self.entries if e.get("phase") == 6]
        return bool(entries) and bool(module("remove_manager").deletion_begun(entries, prefix))

    # Output -------------------------------------------------------------------------------------

    def say(self, text: str = "") -> None:
        """Print a line and keep it for `report.md`

        @param text  the line; empty for a blank line
        """
        self.ctx.console.out(text)
        self.lines.append(text)

    def warn(self, text: str) -> None:
        """Print a line on the error stream and keep it for `report.md`

        @param text  the line
        """
        self.ctx.console.warn(text)
        self.lines.append(text)

    def header(self, number: int) -> None:
        """Begin a phase: set the runner's phase and print the phase's heading

        @param number  the phase number
        """
        self.runner.phase = number
        self.say("")
        self.say(f"== phase {number}: {PHASE_NAMES.get(number, '')}")

    def show(self, action: Action, skipped: bool = False) -> None:
        """Print an action's line, marked when an earlier attempt ran it with `ok`

        @param action   the action
        @param skipped  whether the resume rule skips the action
        """
        mark = "  (ok in an earlier attempt: skipped)" if skipped else ""
        self.say(f"  {action.action_id}: {doctor.describe(action)}{mark}")

    def result_line(self, action: Action, result) -> None:
        """Print an action's result: `ok`, or `failed` with the names that failed

        @param action  the action
        @param result  its result
        """
        if result.ok:
            self.say(f"  {action.action_id}: ok")
            return
        names = [n for n in result.failed if n != action.action_id]
        failed = f" ({', '.join(names)})" if names else ""
        self.say(f"  {action.action_id}: failed{failed}")

    def confirm(self, number: int, what: str = "") -> None:
        """Ask once before a phase marked `confirm` (`--yes` answers); a "no" stops the run

        @param number  the phase number
        @param what    the text that follows the phase's name in the question
        @throws Stop   exit 4 when the answer is no
        """
        phase = self.phase(number)
        if self.dry_run or phase is None or not phase.confirm:
            return
        question = f"Run phase {number} ({phase.name or PHASE_NAMES.get(number, '')}){what}?"
        if self.ctx.confirm(question, default=False):
            self.runner.check_interrupt()
            return
        why = "" if self.ctx.tty else " (no terminal: --yes answers every phase)"
        raise Stop(EXIT_ACTION, [f"phase {number} was not confirmed{why}; the run stops here"])

    # The plan and the host ----------------------------------------------------------------------

    def phase(self, number: int) -> Phase | None:
        """Return the plan's phase of that number

        @param number  the phase number
        @returns       the phase, or None when the plan has none
        """
        return next((p for p in self.plan.phases if p.number == number), None)

    def actions(self, number: int) -> list[Action]:
        """Return the commands of a phase that the run executes, without its notes and manual steps

        @param number  the phase number
        @returns       the actions in plan order; empty when the plan has no such phase
        """
        phase = self.phase(number)
        return [a for a in (phase.actions if phase else []) if a.kind == "command" and not a.manual]

    def fresh_scan(self):
        """Take a new inventory of the host and return it; the probes always run again

        @returns  the scan bundle, which `close` closes
        """
        bundle = scan.build(self.runner, self.environ)
        self.bundles.append(bundle)
        self.bundle = bundle
        self.fresh = list(bundle.result.instances)
        recorded = [rec for rec in self.plan.instances
                    if not any(is_recorded_as(inst, rec.prefix) or any(is_recorded_as(inst, s) for s in rec.spellings)
                               for inst in self.fresh)]
        self.instances = self.fresh + recorded
        return bundle

    def instance(self, prefix: str | None) -> Instance | None:
        """Return the fresh instance of a prefix, else the one the plan records (a prefix phase 6 deleted)

        @param prefix  a prefix as the plan records it, or None
        @returns       the instance, or None when neither the scan nor the plan knows the prefix
        """
        return next((inst for inst in self.instances if is_recorded_as(inst, prefix)), None)

    def fresh_instance(self, prefix: str | None) -> Instance | None:
        """Return the instance of a prefix in the newest scan

        @param prefix  a prefix as the plan records it, or None
        @returns       the instance, or None when the scan does not find it
        """
        return next((inst for inst in self.fresh if is_recorded_as(inst, prefix)), None)

    def fresh_prefix(self, prefix: str) -> str:
        """Return the prefix of the instance a recorded prefix names, as `instance` finds it

        @param prefix  a prefix as the plan records it
        @returns       the instance's prefix, or the prefix itself when no instance has it
        """
        inst = self.instance(prefix)
        return inst.prefix if inst is not None else prefix

    @property
    def target(self) -> Instance | None:
        """Return the target instance, fresh or as the plan records it

        @returns  the instance, or None when neither the scan nor the plan knows the target prefix
        """
        return self.instance(self.plan.target_prefix)

    @property
    def system(self) -> dict[str, Any]:
        """Return the system facts of the newest scan

        @returns  the facts; empty before the first scan
        """
        return self.bundle.result.system if self.bundle is not None else {}

    @property
    def uid(self) -> int:
        """Return the user's uid as the scan found it, else the process's own

        @returns  the uid
        """
        uid = self.system.get("uid")
        return uid if isinstance(uid, int) else os.getuid()

    @property
    def user(self) -> str:
        """Return the user's login name as the scan found it, else the system's

        @returns  the name
        """
        return str(self.system.get("user") or system.login_name())

    @property
    def homebrew_present(self) -> bool:
        """Return whether a Homebrew prefix exists on the host, so MacPorts builds run in trace mode (`-t`)

        @returns  True when the newest scan finds a Homebrew instance
        """
        return any(inst.manager is Manager.BREW for inst in self.fresh)

    def root_files(self) -> RootFiles:
        """Return the run's root form of file writes, made on first use; `close` removes its staging

        @returns  the `RootFiles` of the run
        """
        if self._root_files is None:
            self._root_files = RootFiles(self.runner, self.run_dir.run_id)
        return self._root_files

    def read_source_bin(self) -> dict[str, list[str]]:
        """Return the `bin` entries of each source prefix as the first start found them

        @returns  the entry names by prefix; empty when the record is missing or cannot be read
        """
        try:
            with open(self.run_dir.sub(SOURCE_BIN), encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): [str(n) for n in v] for k, v in data.items() if isinstance(v, list)}

    # The end ------------------------------------------------------------------------------------

    def close(self) -> None:
        """End the start: remove the root staging in cleanup mode, then close every scan

        A failed removal of the staging is passed over, so the exit the run stopped with stands.
        """
        if self._root_files is not None and self._root_files.staging:
            try:
                with self.runner.cleanup():
                    self._root_files.remove_staging()
            except (ActionFailed, EscalationFailed, Interrupted):
                pass
        for bundle in self.bundles:
            bundle.close()

    def write_report(self) -> None:
        """Write `report.md`, always redacted"""
        lines = [f"# brew-ports apply {self.run_dir.run_id}", "",
                 f"plan: {self.plan_path}",
                 f"target: {self.plan.target.value} {self.plan.target_prefix}"]
        for line in self.lines:
            lines.append("## " + line[3:] if line.startswith("== ") else line)
        report.write_markdown(self.run_dir.sub(REPORT_FILE), lines, report.Redactor(home=self.home, user=self.user))

"""The state of one start of an `apply` run, shared by the phase modules

The journal is read as it stood when the start began, so the resume rule weighs earlier starts only.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import os
from collections.abc import Iterator, Sequence
from typing import Any

from . import apply_report, model, plan_report, progress, report, scan, state, system
from .context import Context
from .model import Action, Instance, Manager, Phase, Plan, is_recorded_as
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
DECLINED = "6.declined"          # the journal's record of a no at phase 6: the old managers stay installed


class Stop(Exception):
    """The run ends with `code` once `lines` are printed"""

    def __init__(self, code: int, lines: Sequence[str], error: bool = True) -> None:
        """Stop the run

        @param code   the exit code
        @param lines  why the run stops, printed before it ends; an indented line continues the one above
        @param error  whether something went wrong; False for a stop the user asked for, whose lines print as
                      they are
        """
        super().__init__("; ".join(lines))
        self.code = code
        self.lines = list(lines)
        self.error = error


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
        self.headings: set[int] = set()      # the indexes of the phase headings among `lines`
        self.heading: str | None = None      # the heading of the running phase, until its first line prints
        self.todo: list[str] = []            # what is left for the user to do, said once when the run ends
        self.declined = False                # a no at phase 6 in this start
        self.marking = True                  # whether a command that changes something touches the dirty marker
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
            if not action.read_only and self.marking:
                self.touch()
            return original(action, defer_result=defer_result)
        self.runner.run = run

    @contextlib.contextmanager
    def unmarked(self) -> Iterator[None]:
        """Let a block's commands run without touching the dirty marker

        Phase 1 saves a record and changes nothing a plan describes, so a plan stays good after it.

        @returns  a context manager for the block
        """
        self.marking = False
        try:
            yield
        finally:
            self.marking = True

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

    def flush(self) -> None:
        """Print the heading of the running phase, when it is still to come

        A phase's heading comes with its first line, so a phase that has nothing to say prints nothing.
        """
        if self.heading is None:
            return
        heading, self.heading = self.heading, None
        self.ctx.console.out("")
        self.ctx.console.out(heading)
        self.headings.add(len(self.lines) + 1)
        self.lines += ["", heading]

    def say(self, text: str = "") -> None:
        """Print a line, under its phase's heading, and keep it for `report.md`

        @param text  the line; empty for a blank line
        """
        self.flush()
        self.ctx.console.out(text)
        self.lines.append(text)

    def warn(self, text: str) -> None:
        """Print a line on the error stream and keep it for `report.md`

        @param text  the line
        """
        self.ctx.console.warn(text)
        self.lines.append(text)

    def error(self, text: str) -> None:
        """Print an error under the tool's name and keep it for `report.md`

        @param text  what went wrong
        """
        self.ctx.console.error(text)
        self.lines.append(f"brew-ports: {text}")

    def header(self, number: int) -> None:
        """Begin a phase: set the runner's phase and hold the phase's heading for its first line

        @param number  the phase number
        """
        self.runner.phase = number
        self.heading = apply_report.heading(number, self.plan, self.removed)
        progress.step(self.heading)

    def command(self, action: Action) -> str:
        """Return an action's command as the run shows it

        @param action  the action
        @returns       the command as the user would type it; a long one is cut unless `--verbose` is given
        """
        return plan_report.command(action, self.ctx.console.verbose)

    def show(self, action: Action, skipped: bool = False) -> None:
        """Print a command the phase is about to run, so that its question has something to ask about

        A run under `--yes` asks nothing, so it prints each command once, with its result.

        @param action   the action
        @param skipped  whether an earlier start ran the action, so this one does not
        """
        if self.dry_run or not self.ctx.yes:
            self.say(f"  {self.command(action)}{'   (done in an earlier attempt)' if skipped else ''}")

    def result_line(self, action: Action, result) -> None:
        """Print a command with its result: `ok`, or `failed` with the exit status, who failed and the error line

        @param action  the action
        @param result  its result
        """
        if result.ok:
            self.say(f"  {self.command(action)} ... ok")
            return
        last = result.retry or result
        names = [n for n in result.failed if n != action.action_id]
        line = last.error_line()
        self.say(f"  {self.command(action)} ... failed (exit {last.exit}){' for ' + ', '.join(names) if names else ''}"
                 + (f": {line}" if line else ""))

    @property
    def asks(self) -> bool:
        """Return whether the run puts its questions to the user

        @returns  False for a dry run, under `--yes` and without a terminal
        """
        return not self.dry_run and self.ctx.tty and not self.ctx.yes

    def agreed(self, number: int, question: str = "", stops: str = "") -> bool:
        """Ask once before a phase marked `confirm` (`--yes` answers), and return the answer

        The line above the question says what a no does.

        @param number    the phase number
        @param question  the question; empty for the phase's own
        @param stops     what a no does; empty when it stops the run
        @returns         True for a yes, for a dry run and for a phase that asks nothing
        """
        phase = self.phase(number)
        if self.dry_run or phase is None or not phase.confirm:
            return True
        question = question or apply_report.QUESTIONS[number]
        if self.asks:
            self.say("  " + (stops or apply_report.stops_here(self.run_dir.run_id)))
        answer = self.ctx.confirm(question, default=False)
        if self.asks:
            self.lines.append(f"{question} (y/n) [n] {'y' if answer else 'n'}")
        if not answer:
            return False
        self.runner.check_interrupt()
        return True

    def unconfirmed(self, number: int) -> Stop:
        """Return the stop of a phase that was not confirmed

        @param number  the phase number
        @returns       the stop, exit 4: the user's own no, or the error of a question nobody can answer
        """
        if self.ctx.tty:
            return Stop(EXIT_ACTION, apply_report.declined(number, self.run_dir.run_id), error=False)
        return Stop(EXIT_ACTION, apply_report.unanswered(number, self.run_dir.run_id))

    def confirm(self, number: int) -> None:
        """Ask once before a phase marked `confirm` (`--yes` answers); a "no" stops the run

        @param number  the phase number
        @throws Stop   exit 4 when the answer is no
        """
        if not self.agreed(number):
            raise self.unconfirmed(number)

    @property
    def managers_stay(self) -> bool:
        """Return whether the user answered no at phase 6, in this start or an earlier one

        @returns  True once the answer is given; the journal keeps it for a later start
        """
        return self.declined or any(e.get("action_id") == DECLINED for e in self.entries)

    @property
    def removed(self) -> list[str]:
        """Return the prefixes of the old installations phase 6 uninstalls

        @returns  the prefixes the plan names; none once the user answered no at phase 6
        """
        return [] if self.managers_stay else phase6_prefixes(self.plan)

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
        lines = [f"# brew-ports apply {self.run_dir.run_id}", "", f"Plan: {self.plan_path}", ""]
        lines += ["## " + line if index in self.headings else line for index, line in enumerate(self.lines)]
        report.write_markdown(self.run_dir.sub(REPORT_FILE), lines, report.Redactor(home=self.home, user=self.user))

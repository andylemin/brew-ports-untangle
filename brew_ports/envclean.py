"""`brew-ports env-cleanup` and phase 7: edit the shell files and `/etc/paths` for the surviving instances

The rc files are analysed again with the plan's recorded instances, so a prefix phase 6 deleted is still recognised.
"""

from __future__ import annotations

import dataclasses
import difflib
import hashlib
import os
import re
import shlex
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from . import env, model, scan, state, system
from .context import Context
from .env import PrefixIndex, shell as env_shell
from .homebrew import locate as brew_locate
from .macports import locate as mp_locate
from .model import Action, Instance, Manager, OnFailure, Plan
from .runner import RM, ActionFailed, BaseRunner, RootFiles, StagingError, start_run

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_ACTION = 4

PATH_LISTS = ("PATH", "MANPATH", "INFOPATH", "fish_user_paths")
PREPENDS = ("prepend", "both", "reset")
SYSTEM_RC = ("zprofile", "zshrc", "profile", "bashrc")
STOCK = ("/usr/local/bin", "/usr/local/sbin")
LOGIN_SHELLS = ("zsh", "bash", "sh", "tcsh", "csh", "fish")
CHECKED_AS = {"zsh": "zsh", "bash": "bash", "sh": "sh", "tcsh": "tcsh", "csh": "tcsh", "fish": "fish"}
KEEP = "6.keep."
COMPLETE = "%d.complete"
GUI_PATH = "launchctl config user path"

# An assignment word of the sh family, as the shell analysis finds them.
_ASSIGN = re.compile(r"(?:(?<=[\s;&|(`{])|^)(?:(?:export|declare|typeset|local|readonly)(?:\s+-[A-Za-z]+)*\s+)?"
                     r"[A-Za-z_][A-Za-z0-9_]*\+?=")
# A word list, quoted text or a command substitution, which a csh `set` takes as one value.
_CSH_VALUE = re.compile(r"\([^()]*\)|'[^']*'|\"[^\"]*\"|`[^`]*`")
_BEFORE = "=:\"'( \t"
_AFTER = ":\"' \t);"


# The survivor set ----------------------------------------------------------------------

@dataclass
class Survivors:
    """The instances tested, the prefixes that survive or count as removed, and the primary survivor

    The primary survivor's PATH line must come last.
    """

    instances: list[Instance]
    surviving: list[str]
    removed: list[str]
    primary: str | None
    reasons: dict[str, str] = field(default_factory=dict)

    def instance(self, prefix: str | None) -> Instance | None:
        """Return the tested instance at a prefix

        @param prefix  a prefix as the survivor set records it, or None
        @returns       the instance; None when no tested instance has that prefix
        """
        return next((inst for inst in self.instances if inst.prefix == prefix), None)

    def survivor_instances(self) -> list[Instance]:
        """Return the tested instances that survive

        @returns  the instances, in the order tested
        """
        return [inst for inst in self.instances if inst.prefix in self.surviving]

    def removed_instances(self) -> list[Instance]:
        """Return the tested instances that count as removed

        @returns  the instances, in the order tested
        """
        return [inst for inst in self.instances if inst.prefix in self.removed]

    def brew_survives(self) -> bool:
        """Return whether a Homebrew instance survives, so a line that runs `brew` by name still works

        @returns  True when one of the survivors is a Homebrew instance
        """
        return any(inst.manager is Manager.BREW for inst in self.survivor_instances())


def spells(instance: Instance, text: str | None) -> bool:
    """Return whether `text` is one of the instance's prefix spellings

    Texts compare with `/System/Volumes/Data` dropped and case folded on a case-insensitive volume.

    @param instance  the instance whose prefix and spellings are compared
    @param text      a prefix as text, or None
    @returns         True when the text spells the prefix; False for None or an empty text
    """
    if not text:
        return False
    fold = env.fold_case_for(instance)
    want = system.normalise_text_path(text, fold)
    return any(system.normalise_text_path(s, fold) == want for s in (instance.prefix,) + tuple(instance.spellings))


def _same(a: Instance, b: Instance) -> bool:
    """Return whether two instances are one: the same manager, and a spelling of the second spells the first

    @param a  an instance
    @param b  another
    @returns  True when they are the same instance
    """
    return a.manager is b.manager and any(spells(a, s) for s in (b.prefix,) + tuple(b.spellings))


def tested_instances(fresh: Sequence[Instance], recorded: Sequence[Instance]) -> list[Instance]:
    """Return the fresh instances with the plan's spellings for them, then the recorded ones no fresh one names

    A prefix phase 6 deleted thus keeps its spellings, `brew` path and `owned_roots`.

    @param fresh     the instances of the fresh scan
    @param recorded  the instances the plan records
    @returns         the fresh instances in scan order, then the recorded ones
    """
    out: list[Instance] = []
    for inst in fresh:
        spellings = list(dict.fromkeys(list(inst.spellings) + [s for rec in recorded if _same(inst, rec)
                                                               for s in (rec.prefix,) + tuple(rec.spellings)]))
        out.append(dataclasses.replace(inst, spellings=tuple(spellings)) if spellings != list(inst.spellings) else inst)
    for rec in recorded:
        if not any(_same(inst, rec) for inst in out):
            out.append(rec)
    return out


def _concerns(action_id: str, prefix: str) -> bool:
    """Return whether a phase 6 record acts on a prefix or a path below it

    @param action_id  the record's id, `6.<step>.<subject>`
    @param prefix     the prefix
    @returns          True when the subject is the prefix's slug, or starts with it and a percent sign or a dot
    """
    parts = action_id.split(".", 2)
    if len(parts) < 3:
        return False
    subject, slug = parts[2], state.slug(prefix.rstrip("/"))
    return subject == slug or subject.startswith(slug + "%") or subject.startswith(slug + ".")


def phase6_keeps(journal: state.Journal | None) -> list[str]:
    """Return the prefixes whose last phase 6 record keeps them

    The record is `6.keep.<prefix>`, the prefix as written or with '%' for '/'. A "no" to the second
    confirmation keeps a MacPorts prefix; a resume that deletes it after all ends the keep.

    @param journal  the run's journal, or None
    @returns        the kept prefixes, in the order the journal first keeps them
    """
    kept: dict[str, bool] = {}
    for entry in journal.entries() if journal is not None else []:
        action_id = str(entry.get("action_id") or "")
        if action_id.startswith(KEEP):
            kept[state.unslug(action_id[len(KEEP):])] = True
        elif action_id.startswith("6."):
            for prefix in kept:
                if _concerns(action_id, prefix):
                    kept[prefix] = False
    return [prefix for prefix, keep in kept.items() if keep]


def only_run(plan: Plan | None) -> bool:
    """Return whether the plan migrates only some packages (`--only`)

    @param plan  the plan, or None
    @returns     True for a plan made with `--only`
    """
    return plan is not None and bool(plan.options.get("only"))


def _package_count(bundle, inst: Instance) -> int:
    """Return how many packages the scan found in an instance

    @param bundle  the fresh scan
    @param inst    the instance
    @returns       the number of its formulae, casks or ports
    """
    return sum(1 for pkg in bundle.result.packages if pkg.instance_prefix == inst.prefix)


def _unlistable(inst: Instance) -> bool:
    """Return whether a Homebrew Cellar or Caskroom exists but cannot be listed, so its empty walk proves nothing

    @param inst  an instance; a MacPorts one returns False
    @returns     True when listing either fails for a reason other than its absence
    """
    if inst.manager is not Manager.BREW:
        return False
    for sub in ("Cellar", "Caskroom"):
        path = os.path.join(inst.prefix, sub)
        try:
            os.listdir(path)
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def _judge(bundle, inst: Instance, fresh: bool, target: str | None, keeps: Sequence[str]) -> tuple[bool, str]:
    """Return whether an instance survives, and the reason the report prints

    A prefix counts as removed only when its instance is gone or is known to hold no package.

    @param bundle  the fresh scan
    @param inst    the instance tested
    @param fresh   whether the fresh scan found it; False for one only the plan records
    @param target  the target prefix as text, or None
    @param keeps   the prefixes phase 6 kept
    @returns       whether it survives, and why
    """
    if spells(inst, target):
        return True, "the target"
    if any(spells(inst, prefix) for prefix in keeps):
        return True, "kept by its phase 6 record"
    if not fresh:
        return False, "gone: no instance is found there now"
    if not inst.inventory_known:
        return True, "its packages are unknown (ports-damaged-registry), so it is never known to be empty"
    if _unlistable(inst):
        return True, "its Cellar or Caskroom cannot be listed, so it is never known to be empty"
    count = _package_count(bundle, inst)
    if count:
        return True, f"holds {count} package{'' if count == 1 else 's'}"
    return False, "holds no package"


def _live_path(bundle) -> list[tuple[str, str | None]]:
    """Return `(text, instance prefix)` of each live PATH entry of the scan

    @param bundle  the scan, with its shell analysis or the environment it wrote
    @returns       the entries in PATH order; the prefix is None for an entry no instance owns
    """
    if bundle.analysis is not None:
        return [(e.text, e.instance_prefix) for e in bundle.analysis.live.get("PATH", [])]
    entries = (bundle.result.environment.get("live") or {}).get("PATH") or []
    return [(e.get("text", ""), e.get("instance_prefix")) for e in entries if isinstance(e, dict)]


def _primary(bundle, plan: Plan | None, instances: Sequence[Instance], surviving: Sequence[str],
             target: str | None) -> str | None:
    """Return the primary survivor: the target, except after an `--only` run, where a source stays primary

    That source is the surviving one the live PATH names first, else the first one tested.

    @param bundle     the fresh scan
    @param plan       the plan, or None
    @param instances  the instances tested
    @param surviving  the prefixes that survive
    @param target     the prefix of the target instance, or None
    @returns          the primary survivor's prefix; None when the target does not survive and no source applies
    """
    if plan is not None and only_run(plan):
        sources = [inst.prefix for inst in instances if inst.prefix in surviving
                   and any(spells(inst, s) for s in plan.source_prefixes)]
        if sources:
            for _, prefix in _live_path(bundle):
                if prefix in sources:
                    return prefix
            return sources[0]
    return target if target in surviving else None


def survivors(bundle, plan: Plan | None, journal: state.Journal | None = None, *,
              target_prefix: str | None = None) -> Survivors:
    """Return the survivor set from a fresh `bundle`, the plan's recorded instances and the journal's keeps

    @param bundle         the fresh scan
    @param plan           the plan, whose recorded instances are tested too; None for none
    @param journal        the run's journal, whose phase 6 keeps survive; None for none
    @param target_prefix  the target when there is no plan, or one that overrides the plan's
    @returns              each instance tested, whether it survives and why, and the primary survivor
    """
    fresh = list(bundle.result.instances)
    instances = tested_instances(fresh, list(plan.instances) if plan is not None else [])
    target_text = target_prefix or (plan.target_prefix if plan is not None else None)
    keeps = phase6_keeps(journal)
    surviving: list[str] = []
    removed: list[str] = []
    reasons: dict[str, str] = {}
    for number, inst in enumerate(instances):
        survives, why = _judge(bundle, inst, number < len(fresh), target_text, keeps)
        (surviving if survives else removed).append(inst.prefix)
        reasons[inst.prefix] = why
    target = next((inst.prefix for inst in instances if spells(inst, target_text)), None)
    return Survivors(instances, surviving, removed, _primary(bundle, plan, instances, surviving, target), reasons)


def survivor_lines(surv: Survivors) -> list[str]:
    """Return the report lines of a survivor set: each instance, whether it survives, and why

    @param surv  the survivor set
    @returns     one line per instance tested, the primary survivor marked
    """
    lines = []
    for inst in surv.instances:
        state_text = "survives" if inst.prefix in surv.surviving else "counts as removed"
        primary = ", the primary survivor" if inst.prefix == surv.primary else ""
        lines.append(f"{inst.prefix} {state_text} ({surv.reasons.get(inst.prefix, '')}{primary})")
    return lines


# Runs and plans ---------------------------------------------------------------------------

def read_plan(path: str) -> Plan:
    """Read a run's `plan.json`

    @param path             the file
    @returns                the plan it holds
    @throws OSError         when the file cannot be read
    @throws ValueError      when it holds no JSON, or a field holds an unknown value
    @throws TypeError       when the JSON lacks a field a plan needs, or a value has the wrong shape
    @throws AttributeError  when a dict field holds a list or a scalar
    """
    with open(path, encoding="utf-8") as fh:
        return model.from_json(Plan, fh.read())


def phase_completed(run_dir: state.RunDir, number: int) -> bool:
    """Return whether a run finished a phase: an `ok` result of its `complete` record, or a later phase's entry

    @param run_dir  the run directory, whose journal is read
    @param number   the phase, whose record is `<number>.complete`
    @returns        True once the phase is complete
    """
    for entry in run_dir.journal.entries():
        if entry.get("action_id") == COMPLETE % number and entry.get("result") == "ok":
            return True
        phase = entry.get("phase")
        if isinstance(phase, int) and not isinstance(phase, bool) and number < phase <= 8:
            return True
    return False


def latest_completed(state_dir: state.StateDir) -> tuple[state.RunDir, Plan] | None:
    """Return the newest run that holds a plan and whose phase 5 completed, with its plan

    @param state_dir        the state directory, whose runs are tried newest first
    @returns                the run directory and its plan; None when no run qualifies
    @throws OSError         when that run's `plan.json` cannot be read
    @throws ValueError      when it holds no JSON, or a field holds an unknown value
    @throws TypeError       when the JSON lacks a field a plan needs, or a value has the wrong shape
    @throws AttributeError  when a dict field holds a list or a scalar
    """
    for run_id in reversed(state_dir.run_ids()):
        run_dir = state.RunDir(os.path.join(state_dir.runs, run_id))
        path = run_dir.sub("plan.json")
        if os.path.isfile(path) and phase_completed(run_dir, 5):
            return run_dir, read_plan(path)
    return None


# Edits ----------------------------------------------------------------------------------------

@dataclass
class Edit:
    """One file's cleanup: its text before and after, the unified diff and the operations applied

    When `manual` says why the tool never writes the file, the diff is the edit to make by hand.
    """

    path: str                        # the file as the shell reads it
    kind: str                        # "rc", "etc" (written as root), "launchd" (the GUI PATH, printed only) or "note"
    old_text: str | None          # None: the PATH line edit creates the file
    new_text: str | None          # None: a system paths edit removes the file
    diff: str
    ops: list[str] = field(default_factory=list)
    shell: str | None = None      # the parser that checks the rewrite
    realpath: str | None = None   # what is written
    manual: str | None = None     # why the tool never writes it
    notes: list[str] = field(default_factory=list)    # report-only lines: dead entries, lines left as they are
    command: list[str] = field(default_factory=list)  # launchd: the command to run by hand
    fish: str | None = None       # a surviving fish for the check of a fish file
    etc_rel: str | None = None    # an /etc file below /etc, for its copy under <run>/backup/etc/

    @property
    def changed(self) -> bool:
        """Return whether the edit changes the file

        @returns  True when the text after differs from the text before
        """
        return self.old_text != self.new_text


def unified_diff(path: str, old: str | None, new: str | None) -> str:
    """Return the unified diff of a file's edit, `/dev/null` standing for a side that does not exist

    @param path  the file's name in the diff's headers
    @param old   the text before; None when the edit creates the file
    @param new   the text after; None when the edit removes the file
    @returns     the diff, each of its lines ending in a newline; empty when the texts are equal
    """
    lines = difflib.unified_diff((old or "").splitlines(True), (new or "").splitlines(True),
                                 fromfile=path if old is not None else "/dev/null",
                                 tofile=path if new is not None else "/dev/null")
    return "".join(line if line.endswith("\n") else line + "\n" for line in lines)


def _ending(line: str) -> str:
    """Return the line ending of a line

    @param line  a line as `splitlines(True)` keeps it
    @returns     its carriage return, line feed or both; empty for a last line without one
    """
    return line[len(line.rstrip("\r\n")):]


class _Text:
    """The lines of one file and the operations on them, by the analysis' 1-based `str.splitlines` numbers"""

    def __init__(self, text: str | None) -> None:
        """Hold a file's text with no operation applied

        @param text  the file's text; None for a file that does not exist or cannot be read
        """
        self.old = text
        self.lines = text.splitlines(True) if text else []
        self.new: dict[int, str | None] = {}
        self.after: dict[int, list[str]] = {}

    def current(self, lineno: int) -> str | None:
        """Return the line with the edits so far, without its line ending

        @param lineno  the line's 1-based number
        @returns       the line; None once deleted, or for a number outside the file
        """
        if lineno in self.new:
            value = self.new[lineno]
            return None if value is None else value.rstrip("\r\n")
        if 0 < lineno <= len(self.lines):
            return self.lines[lineno - 1].rstrip("\r\n")
        return None

    def delete(self, lineno: int) -> None:
        """Drop a line

        @param lineno  the line's 1-based number
        """
        self.new[lineno] = None

    def replace(self, lineno: int, text: str) -> None:
        """Replace a line's text, keeping its line ending

        @param lineno  the line's 1-based number
        @param text    the replacement, without a line ending
        """
        self.new[lineno] = text + _ending(self.lines[lineno - 1])

    def insert_after(self, lineno: int, text: str) -> None:
        """Add a line after another; the lines added after one line keep their order

        @param lineno  the 1-based number of the line it follows; 0 for the top of the file
        @param text    the line, without a line ending
        """
        self.after.setdefault(lineno, []).append(text + "\n")

    def append(self, text: str) -> None:
        """Add a line at the end of the file

        @param text  the line, without a line ending
        """
        self.insert_after(len(self.lines), text)

    def render(self) -> str:
        """Return the file's text with its lines replaced, dropped and added

        @returns  the text; a last line without a line ending gets one before a line added after it
        """
        out = list(self.after.get(0, []))
        for number, line in enumerate(self.lines, 1):
            current = self.new.get(number, line)
            if current is not None:
                out.append(current)
            extra = self.after.get(number)
            if extra:
                if out and not out[-1].endswith(("\n", "\r")):
                    out[-1] += "\n"
                out.extend(extra)
        return "".join(out)


class _File:
    """One rc file under cleanup: its text, records, operations and notes"""

    def __init__(self, path: str, shell: str, text: str | None, records: Sequence[env_shell.LineRecord],
                 blocks: Sequence[env_shell.InstallerBlock]) -> None:
        """Start a file's cleanup with no operation and no note

        @param path     the file as the shell reads it
        @param shell    the shell whose parser checks the rewrite
        @param text     the file's text; None when it does not exist or cannot be read
        @param records  the analysis' records of the file
        @param blocks   the installer blocks in the file
        """
        self.path = path
        self.shell = shell
        self.text = _Text(text)
        self.records = list(records)
        self.blocks = list(blocks)
        self.ops: list[str] = []
        self.notes: list[str] = []
        self.manual: str | None = None
        self.frozen = False          # unreadable, not UTF-8, or changed since the analysis: no edit at all

    def by_line(self) -> list[tuple[int, list[env_shell.LineRecord]]]:
        """Return the file's records grouped by line

        @returns  each line number with its records, in line order
        """
        lines: dict[int, list[env_shell.LineRecord]] = {}
        for rec in self.records:
            lines.setdefault(rec.lineno, []).append(rec)
        return sorted(lines.items())


def _family(shell: str) -> str:
    """Return the syntax family of a shell

    @param shell  zsh, bash, sh, tcsh, csh or fish
    @returns      `csh` for tcsh and csh, `fish` for fish, else `sh`
    """
    if shell in ("tcsh", "csh"):
        return "csh"
    return "fish" if shell == "fish" else "sh"


def _csh_assigned(code: str) -> int:
    """Return how many variables the csh commands of a line assign: one per `setenv` or `@`, each name of a `set`

    A name of `set` takes the `= value` after it or stands bare, so `set a = x b` assigns two.

    @param code  the line, its comment stripped
    @returns     the number of variables
    """
    count = 0
    for command in env_shell.split_commands(code):
        words = _CSH_VALUE.sub("x", command).replace("+=", "=").replace("=", " = ").split()
        if words[:1] in (["setenv"], ["@"]):
            count += 1
        elif words[:1] == ["set"]:
            i = 1
            while i < len(words) and words[i].startswith("-"):
                i += 1
            while i < len(words):
                count += 1
                i += 3 if words[i + 1:i + 2] == ["="] else 1
    return count


def path_line(instance: Instance, shell: str) -> str:
    """Return an instance's PATH line in a shell's syntax: `brew shellenv`, or the `bin` and `sbin` prepend

    @param instance  the instance the line puts in front
    @param shell     the shell that reads the line
    @returns         the line, without a line ending
    """
    family = _family(shell)
    if instance.manager is Manager.BREW:
        brew = os.path.join(instance.prefix, "bin", "brew")
        if family == "csh":
            return f"eval `{brew} shellenv`"
        if family == "fish":
            return f"eval ({brew} shellenv)"
        return f'eval "$({brew} shellenv)"'
    bin_dir, sbin_dir = os.path.join(instance.prefix, "bin"), os.path.join(instance.prefix, "sbin")
    if family == "csh":
        return f'setenv PATH "{bin_dir}:{sbin_dir}:$PATH"'
    if family == "fish":
        return f"set -gx PATH {bin_dir} {sbin_dir} $PATH"
    return f'export PATH="{bin_dir}:{sbin_dir}:$PATH"'


def neutral_line(line: str, prefix: str) -> str:
    """Return `true  # brew-ports: <prefix> removed: <original line>`, indented like the line

    `true` does nothing, and the comment keeps the original line. `_Cleanup.line` neutralises only a line outside
    every compound command.

    @param line    the line, without its line ending
    @param prefix  the removed prefix the line names
    @returns       the line that takes its place
    """
    indent = line[:len(line) - len(line.lstrip(" \t"))]
    return f"{indent}true  # brew-ports: {prefix} removed: {line.strip()}"


def _drop_one(line: str, text: str) -> str | None:
    """Return `line` without every whole-element occurrence of `text` in its code

    A `:`-list element goes with one of its colons, a word with its blanks.

    @param line  the line as written
    @param text  a PATH entry as written
    @returns     the line without the entry; None when the entry is no whole element of the code
    """
    found = False
    start = 0
    while True:
        end = len(env_shell.strip_comment(line))
        i = line.find(text, start, end)
        if i < 0:
            return line if found else None
        j = i + len(text)
        before = line[i - 1] if i > 0 else ""
        after = line[j] if j < end else ""
        if before not in _BEFORE or before == "" or (after and after not in _AFTER):
            start = i + 1
            continue
        if after == ":":
            line = line[:i] + line[j + 1:]
        elif before == ":":
            line = line[:i - 1] + line[j:]
        elif after in (" ", "\t"):
            k = j
            while k < len(line) and line[k] in " \t":
                k += 1
            line = line[:i] + line[k:]
        elif before in (" ", "\t"):
            k = i
            while k > 0 and line[k - 1] in " \t":
                k -= 1
            line = line[:k] + line[j:]
        else:
            return None
        found = True
        start = max(0, i - 1)


def drop_entries(line: str, texts: Sequence[str]) -> str | None:
    """Return the line without the given PATH entries, as written

    @param line   the line as written
    @param texts  the entries to drop, as written
    @returns      the line; None when one of the entries is no whole element of it
    """
    for text in dict.fromkeys(texts):
        result = _drop_one(line, text)
        if result is None:
            return None
        line = result
    return line


def _read_text(path: str) -> tuple[str | None, str | None]:
    """Return a file's text, or why it is left alone (unreadable, not UTF-8)

    @param path  the file
    @returns     the text and None, or None and the reason
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return None, f"{path} cannot be read: {exc.strerror or exc}"
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, f"{path} is not UTF-8 text: edit it by hand"


class _ScanProbes:
    """A runner that refuses the analysis' one probe, `launchctl getenv PATH`: the GUI PATH comes from the scan"""

    phase = None

    def run(self, action: Action):
        """Refuse a probe

        @param action    the probe
        @throws OSError  always, which the analysis takes for a failed probe
        """
        raise OSError(f"{action.action_id} is answered from the scan")


@dataclass
class _Prepend:
    """A line of the login shell's files that puts a survivor's `bin` in front"""

    index: int                       # the file's place in the read order
    lineno: int
    winner: str                      # the survivor in front once the line has run
    names_primary: bool
    record: env_shell.LineRecord

    def position(self) -> tuple[int, int]:
        """Return where the line runs: its file's place in the read order, then its line number

        @returns  the pair, which orders the prepends as the login shell runs them
        """
        return self.index, self.lineno


class _Cleanup:
    """The environment edits over one shell analysis"""

    def __init__(self, analysis: env_shell.ShellAnalysis, surv: Survivors, home: str, environ: Mapping[str, str], *,
                 etc_dir: str, uid: int) -> None:
        """Index the surviving instances: their `bin` and `sbin` under every spelling, and their `fish`

        @param analysis  the shell analysis
        @param surv      the instances that survive and the ones that count as removed
        @param home      the user's home
        @param environ   the environment
        @param etc_dir   the system directory that holds the shells' rc files and `paths`
        @param uid       whose rc files the tool may write
        """
        self.analysis = analysis
        self.surv = surv
        self.home = home
        self.environ = dict(environ)
        self.etc_dir = os.path.normpath(etc_dir)
        self.uid = uid
        self.removed = set(surv.removed)
        self.surviving = set(surv.surviving)
        self.brew_left = surv.brew_survives()
        self.files: dict[str, _File] = {}
        self.alias: dict[str, str] = {}
        self.bins: dict[str, str] = {}
        for inst in surv.survivor_instances():
            for spelling in (inst.prefix,) + tuple(inst.spellings):
                for sub in ("bin", "sbin"):
                    self.bins[system.normalise_text_path(os.path.join(spelling, sub), False)] = inst.prefix
        self.fish = next((p for p in (os.path.join(i.prefix, "bin", "fish") for i in surv.survivor_instances())
                          if os.access(p, os.X_OK)), None)

    # Records ---------------------------------------------------------------------------

    def gone(self, rec: env_shell.LineRecord) -> list[env_shell.PathEntry]:
        """Return the entries of a record under a removed prefix, never the stock `/usr/local/bin` and `sbin`

        @param rec  a record of the analysis
        @returns    the entries, in line order
        """
        return [e for e in rec.entries if e.instance_prefix in self.removed
                and not (e.path and os.path.normpath(e.path) in STOCK)]

    def removed_prefix(self, recs: Iterable[env_shell.LineRecord]) -> str:
        """Return the removed prefix a line names, for its notes and its neutral line

        @param recs  the records of the line
        @returns     the first removed prefix they name; else the removed Homebrew prefixes, or `Homebrew`
        """
        for rec in recs:
            for prefix in [e.instance_prefix for e in self.gone(rec)] + list(rec.instance_prefixes):
                if prefix in self.removed:
                    return prefix
        brews = [inst.prefix for inst in self.surv.removed_instances() if inst.manager is Manager.BREW]
        return ", ".join(brews) or "Homebrew"

    def action(self, rec: env_shell.LineRecord) -> str | None:
        """Return what the edits do with one record

        A line that runs `brew` by name names the removed Homebrew once no Homebrew survives.

        @param rec  a record of the analysis
        @returns    "drop", "rewrite" or "neutralise"; None to leave the record as it is
        """
        gone = self.gone(rec)
        by_name = rec.brew == "" and not self.brew_left
        if rec.kind == "shellenv":
            owners = list(rec.instance_prefixes)
            return "drop" if any(p in self.removed for p in owners) or (not owners and by_name) else None
        if rec.kind == "assign" and rec.var in PATH_LISTS:
            if gone:
                return "drop" if len(gone) == len(rec.entries) else "rewrite"
            return "neutralise" if by_name else None
        if rec.kind in ("dyld", "build"):
            if gone:
                return "drop"
            return "neutralise" if by_name else None
        if rec.kind == "source":
            return "neutralise" if gone or by_name else None
        return None

    def unrecorded(self, f: _File, code: str, recs: Sequence[env_shell.LineRecord]) -> bool:
        """Return whether a line of the sh or csh family holds assignments the analysis did not record

        Deleting or neutralising such a line, as `export PATH=... EDITOR=vim` or `set path = (...) prompt = x`, would
        lose them. A fish `set` assigns one variable.

        @param f     the file that holds the line
        @param code  the line
        @param recs  the line's records
        @returns     True when the line holds more assignments than assignment records
        """
        family = _family(f.shell)
        if family == "fish":
            return False
        recorded = sum(1 for rec in recs if rec.kind in ("assign", "dyld", "build"))
        code = env_shell.strip_comment(code)
        return (len(_ASSIGN.findall(code)) if family == "sh" else _csh_assigned(code)) > recorded

    def covered(self, f: _File, raw: str, recs: Sequence[env_shell.LineRecord]) -> bool:
        """Return whether a line holds nothing but what its records remove, so it may be deleted or neutralised

        No entry of a record stays, the analysis recorded every assignment `unrecorded` counts, and each command on
        the line names a removed path, runs `brew` by name once no Homebrew survives, or exports a variable a record
        assigns.

        @param f     the file that holds the line
        @param raw   the line as written
        @param recs  the line's records, every one of which the edits act on
        @returns     True when deleting or neutralising the line loses nothing else
        """
        by_name = not self.brew_left
        names: list[str] = []
        for rec in recs:
            gone = self.gone(rec)
            if rec.kind == "shellenv":
                names += [rec.brew] if rec.brew else []
            elif all(e in gone or (by_name and env_shell.runs_brew_by_name(e.text)) for e in rec.entries):
                names += [e.text for e in gone]
            else:
                return False
        if self.unrecorded(f, raw, recs):
            return False
        variables = {rec.var for rec in recs if rec.var}
        for command in env_shell.split_commands(env_shell.strip_comment(raw)):
            words = env_shell.split_words(command)
            if not (any(name in command for name in names) or (by_name and env_shell.runs_brew_by_name(command))
                    or (words[:1] == ["export"] and set(words[1:]) <= variables)):
                return False
        return True

    def line(self, f: _File, lineno: int, recs: list[env_shell.LineRecord]) -> None:
        """Apply the edits to one line; a compound line, or one they cannot rewrite, is left for a hand edit

        @param f       the file that holds the line
        @param lineno  the line's number
        @param recs    the line's records, markers left out
        """
        active = [(rec, act) for rec, act in ((rec, self.action(rec)) for rec in recs) if act]
        if not active:
            return
        raw = recs[0].text
        prefix = self.removed_prefix(rec for rec, _ in active)
        if any(rec.compound for rec, _ in active):
            f.notes.append(f"line {lineno} left as it is: it opens or continues a compound command, "
                           f"and it names {prefix}: {raw.strip()}")
            return
        kinds = {act for _, act in active}
        whole = kinds <= {"drop", "neutralise"} and len(active) == len(recs) and self.covered(f, raw, recs)
        if whole and "neutralise" in kinds:
            f.text.replace(lineno, neutral_line(raw, prefix))
            f.ops.append(f"sourced files, line {lineno}: neutralised `{raw.strip()}`")
            return
        if whole:
            labels = sorted({"build exports" if rec.kind in ("dyld", "build") else "manager setup"
                             for rec, _ in active})
            f.text.delete(lineno)
            f.ops.append(f"{' and '.join(labels)}, line {lineno}: removed `{raw.strip()}`")
            return
        text = f.text.current(lineno) or ""
        for rec, act in active:
            if rec.kind != "assign" or act == "neutralise" or (act == "drop" and not rec.self_ref):
                f.notes.append(f"line {lineno} names {prefix} and holds more than this cleanup removes: "
                               f"edit it by hand: {raw.strip()}")
                return
            rewritten = drop_entries(text, [e.text for e in self.gone(rec)])
            if rewritten is None:
                f.notes.append(f"line {lineno}: the entries under {prefix} could not be located in the text: "
                               f"edit it by hand: {raw.strip()}")
                return
            text = rewritten
        f.text.replace(lineno, text)
        f.ops.append(f"path entries, line {lineno}: `{raw.strip()}` -> `{text.strip()}`")

    def names_survivor(self, rec: env_shell.LineRecord) -> bool:
        """Return whether a record names a surviving prefix

        @param rec  a record of the analysis
        @returns    True when one of its entries or its prefixes survives
        """
        prefixes = [e.instance_prefix for e in rec.entries] + list(rec.instance_prefixes)
        return any(p in self.surviving for p in prefixes)

    def blocks(self, f: _File) -> None:
        """Remove the two marker lines of an installer block whose lines name a removed prefix and no survivor

        @param f  the file that holds the blocks
        """
        for block in f.blocks:
            inner = [r for r in f.records if block.start < r.lineno < block.end and r.kind != "marker"]
            removed = any(self.gone(r) or any(p in self.removed for p in r.instance_prefixes) for r in inner)
            if removed and not any(self.names_survivor(r) for r in inner):
                f.text.delete(block.start)
                f.text.delete(block.end)
                f.ops.append(f"manager setup, lines {block.start} and {block.end}: removed the markers of the "
                             f"MacPorts installer block for {block.var}")

    def dead_entries(self, f: _File) -> None:
        """Note the PATH assignments that drop `$PATH`, and the entries whose directory is missing

        @param f  the file that holds the assignments
        """
        for rec in f.records:
            if rec.kind != "assign" or rec.var not in PATH_LISTS or f.text.current(rec.lineno) is None:
                continue
            if rec.var == "PATH" and rec.position == "reset":
                f.notes.append(f"dead entries, line {rec.lineno}: drops $PATH, which discards /etc/paths: "
                               f"{rec.text.strip()}")
            for entry in rec.entries:
                if entry.exists is False and entry.instance_prefix not in self.removed:
                    f.notes.append(f"dead entries, line {rec.lineno}: {entry.text} does not exist")

    # Files -----------------------------------------------------------------------------

    def system_file(self, path: str) -> bool:
        """Return whether a path is one of the system rc files, which the tool never edits

        @param path  a shell file
        @returns     True for `zprofile`, `zshrc`, `profile` or `bashrc` in the system directory
        """
        return os.path.dirname(os.path.normpath(path)) == self.etc_dir and os.path.basename(path) in SYSTEM_RC

    def manual_reason(self, path: str, rc: env_shell.RcFile | None) -> str | None:
        """Return why the tool never writes the file: a system rc file, or another user's (a Nix store)

        @param path  the file as the shell reads it
        @param rc    the analysis' record of the file, or None
        @returns     the reason; None when the tool may write the file
        """
        if self.system_file(path):
            return f"the tool never edits {path}: make this edit by hand"
        if rc is not None and rc.owner_uid is not None and rc.owner_uid != self.uid:
            return f"{rc.realpath or path} belongs to uid {rc.owner_uid}, not to you: make this edit by hand"
        return None

    def load(self) -> None:
        """Load one `_File` per `realpath`; a second rc name linked to the same file is an alias of the first"""
        seen: dict[str, str] = {}
        for rc in self.analysis.files:
            if not rc.exists:
                continue
            real = rc.realpath or rc.path
            if real in seen:
                self.alias[rc.path] = seen[real]
                continue
            seen[real] = rc.path
            text, problem = (None, rc.error) if rc.error else _read_text(rc.path)
            f = _File(rc.path, rc.shell, text, [r for r in self.analysis.records if r.file == rc.path],
                      [b for b in self.analysis.blocks if b.file == rc.path])
            f.manual = self.manual_reason(rc.path, rc)
            if problem:
                f.frozen = True
                if f.records:
                    f.notes.append(f"left alone: {problem}")
            elif any(f.text.current(r.lineno) != r.text for r in f.records):
                f.frozen = True
                f.notes.append("left alone: the file changed while it was being read")
            self.files[rc.path] = f

    def rc_ops(self) -> None:
        """Run the per-line edits, the installer blocks and the dead-entry notes over every rc file"""
        for f in self.files.values():
            if f.frozen:
                continue
            for lineno, recs in f.by_line():
                self.line(f, lineno, [r for r in recs if r.kind != "marker"])
            self.blocks(f)
            self.dead_entries(f)

    # PATH line and PATH order ----------------------------------------------------------

    def login_file(self, shell: str) -> str:
        """Return the login file of the user's shell, which the PATH line edit adds to

        @param shell  the login shell's name
        @returns      the file's path, which need not exist
        """
        home = self.home
        if shell == "zsh":
            return os.path.join(self.analysis.zdotdir or home, ".zprofile")
        if shell == "bash":
            names = (".bash_profile", ".bash_login", ".profile")
            return next((os.path.join(home, n) for n in names if os.path.isfile(os.path.join(home, n))),
                        os.path.join(home, ".bash_profile"))
        if shell == "sh":
            return os.path.join(home, ".profile")
        if shell in ("tcsh", "csh"):
            tcshrc, cshrc = os.path.join(home, ".tcshrc"), os.path.join(home, ".cshrc")
            return cshrc if not os.path.isfile(tcshrc) and os.path.isfile(cshrc) else tcshrc
        return env_shell.fish_config(home, self.environ)

    def file_for(self, path: str, shell: str) -> _File:
        """Return the `_File` the login shell reads at `path`; the PATH line edit creates a missing login file

        @param path   a file the login shell reads
        @param shell  the login shell's name
        @returns      the file's cleanup: the loaded one, that of the file it aliases, or one made here
        """
        path = self.alias.get(path, path)
        f = self.files.get(path)
        if f is None:
            exists = os.path.lexists(path)
            text, problem = _read_text(path) if exists else (None, None)
            f = _File(path, CHECKED_AS[shell], text, [], [])
            f.manual = self.manual_reason(path, None)
            if exists and f.manual is None:
                uid = os.stat(os.path.realpath(path)).st_uid if os.path.exists(path) else None
                if uid is not None and uid != self.uid:
                    f.manual = f"{os.path.realpath(path)} belongs to uid {uid}, not to you: make this edit by hand"
            if problem:
                f.frozen = True
                f.notes.append(f"left alone: {problem}")
            self.files[path] = f
        return f

    def owners(self, rec: env_shell.LineRecord) -> list[str]:
        """Return the survivors whose `bin` or `sbin` a prepend puts in front, in line order

        @param rec  a record of the analysis
        @returns    their prefixes; empty for a record that puts no survivor in front
        """
        if rec.kind == "shellenv":
            if rec.instance_prefixes:
                return [p for p in rec.instance_prefixes if p in self.surviving]
            brews = [i.prefix for i in self.surv.survivor_instances() if i.manager is Manager.BREW]
            return brews if rec.brew == "" and len(brews) == 1 else []
        if rec.kind == "assign" and rec.var in ("PATH", "fish_user_paths") and rec.position in PREPENDS:
            out = []
            for entry in rec.entries:
                owner = self.bins.get(system.normalise_text_path(entry.path, False)) if entry.path else None
                if owner:
                    out.append(owner)
            return out
        return []

    def prepends(self, files: Sequence[_File]) -> list[_Prepend]:
        """Return the lines still in place that put a survivor in front, each with the survivor in front after it

        @param files  the login shell's files, in read order
        @returns      the prepends, in the order the login shell runs them
        """
        out = []
        for index, f in enumerate(files):
            for lineno, recs in f.by_line():
                if f.text.current(lineno) is None:
                    continue
                winner, named, last = None, False, recs[-1]
                for rec in recs:
                    owners = self.owners(rec)
                    if owners:
                        winner, last = owners[0], rec
                        named = named or self.surv.primary in owners
                if winner:
                    out.append(_Prepend(index, lineno, winner, named, last))
        return out

    def collapse(self, f: _File) -> None:
        """Collapse duplicate `brew shellenv` lines inside one file to the last

        @param f  a file the login shell reads
        """
        groups: dict[str, list[env_shell.LineRecord]] = {}
        for rec in f.records:
            if rec.kind == "shellenv" and not rec.compound and f.text.current(rec.lineno) is not None:
                key = system.normalise_text_path(rec.brew, False) if rec.brew else ""
                groups.setdefault(key, []).append(rec)
        for recs in groups.values():
            for rec in recs[:-1]:
                f.text.delete(rec.lineno)
                f.ops.append(f"PATH order, line {rec.lineno}: removed a duplicate of line {recs[-1].lineno}, "
                             f"`{rec.text.strip()}`")

    @staticmethod
    def anchor(f: _File, prepend: _Prepend) -> int:
        """Return the line after which the primary survivor's line goes

        That is the prepend itself, the end marker of its installer block, or the last line of its continuation.

        @param f        the file that holds the prepend
        @param prepend  the last prepend of another survivor
        @returns        the line's number
        """
        lineno = prepend.lineno
        block = next((b for b in f.blocks if b.start < lineno < b.end), None)
        if block is not None and f.text.current(block.end) is not None:
            return block.end
        while True:
            text = f.text.current(lineno) or ""
            count = len(text) - len(text.rstrip("\\"))
            if count % 2 == 0 or f.text.current(lineno + 1) is None:
                return lineno
            lineno += 1

    def live_first(self, primary: Instance) -> bool:
        """Return whether the live PATH has `<prefix>/bin` before `/usr/bin`, so no PATH line is needed

        @param primary  the primary survivor
        @returns        True when its `bin` comes first
        """
        entries = self.analysis.live.get("PATH") or []
        own = env_shell.path_index(entries, os.path.join(primary.prefix, "bin"))
        usr_bin = env_shell.path_index(entries, "/usr/bin")
        return own is not None and (usr_bin is None or own < usr_bin)

    def order(self) -> list[str]:
        """Apply the PATH line and PATH order edits to the login shell's files

        `.zshenv` is left out for zsh, because `/etc/zprofile` runs `path_helper` after it.

        @returns  a note on why no PATH line is added or reordered; empty when the edits ran
        """
        shell = os.path.basename(self.analysis.login_shell or "")
        primary = self.surv.instance(self.surv.primary)
        if primary is None:
            return ["PATH line and PATH order: no primary survivor, so no PATH line is added or moved"]
        if shell not in LOGIN_SHELLS:
            return ["PATH line and PATH order: the login shell "
                    f"{self.analysis.login_shell or '(unknown)'} is none of {', '.join(LOGIN_SHELLS)}, "
                    "so no PATH line is added or moved"]
        paths = [p for p in self.analysis.read_order if not self.system_file(p)]
        if shell == "zsh":
            paths = [p for p in paths if os.path.basename(p) != ".zshenv"]
        login = self.login_file(shell)
        if login not in paths:
            paths.insert(0, login)
        files = [self.file_for(p, shell) for p in paths]
        if any(f.frozen for f in files):
            return ["PATH line and PATH order: a file the login shell reads is left alone, so no PATH line is added "
                    "or moved"]
        for f in files:
            self.collapse(f)
        lines = self.prepends(files)
        if not any(line.names_primary for line in lines):
            if self.live_first(primary):
                return [f"PATH line: {primary.prefix}/bin already comes before /usr/bin on the live PATH, "
                        "so no PATH line is added"]
            index = paths.index(login)
            f = files[index]
            text = path_line(primary, shell)
            f.text.append(text)
            f.ops.append(f"PATH line: added the line of {primary.prefix}")
            end = len(f.text.lines) + 1
            lines.append(_Prepend(index, end, primary.prefix, True, env_shell.LineRecord(f.path, end, text, "assign")))
        self.reorder(files, lines, primary, shell)
        return []

    def reorder(self, files: Sequence[_File], lines: Sequence[_Prepend], primary: Instance, shell: str) -> None:
        """Make the primary survivor's line the last prepend: move it within one file, or copy it after a later one

        A last prepend inside a block, an array or a quote that spans lines is only noted: no line goes into it.

        @param files    the login shell's files, in read order
        @param lines    the prepends, as `prepends` returns them
        @param primary  the primary survivor
        @param shell    the login shell's name
        """
        others = [line for line in lines if line.winner != primary.prefix]
        if not others:
            return
        last = max(others, key=_Prepend.position)
        mine = [line for line in lines if line.winner == primary.prefix]
        if mine and max(line.position() for line in mine) > last.position():
            return
        f = files[last.index]
        if last.record.nested:
            f.notes.append(f"PATH order: line {last.lineno}, the PATH line of {last.winner}, is inside a compound "
                           f"command, so the PATH line of {primary.prefix} is not put after it: make it the last "
                           "PATH line by hand")
            return
        anchor = self.anchor(f, last)
        here = [line for line in mine if line.index == last.index]
        if here and not here[-1].record.compound:
            moved = here[-1]
            text = f.text.current(moved.lineno) or ""
            f.text.delete(moved.lineno)
            f.text.insert_after(anchor, text)
            f.ops.append(f"PATH order, line {moved.lineno}: moved below line {last.lineno}, "
                         f"the PATH line of {last.winner}")
            return
        indent_of = f.text.current(last.lineno) or ""
        indent = indent_of[:len(indent_of) - len(indent_of.lstrip(" \t"))]
        f.text.insert_after(anchor, indent + path_line(primary, shell))
        f.ops.append(f"PATH order: added the PATH line of {primary.prefix} after line {last.lineno}, "
                     f"the PATH line of {last.winner}")

    # System paths and the GUI PATH -------------------------------------------------------

    def etc_edits(self) -> list[Edit]:
        """Return the system paths edits: `/etc/paths` and `/etc/paths.d` minus the lines naming a removed prefix

        Stock lines stay, and a `/etc/paths.d` file with no line left is removed.

        @returns  one edit per file with a line to drop; one that cannot be read gets a manual edit with its reason
        """
        by_file: dict[str, list[env_shell.EtcPathLine]] = {}
        for item in self.analysis.etc_paths:
            by_file.setdefault(item.file, []).append(item)
        paths_file = os.path.join(self.etc_dir, "paths")
        edits = []
        for path, items in sorted(by_file.items()):
            drop = {i.lineno for i in items if not i.stock and i.entry.instance_prefix in self.removed
                    and os.path.normpath(i.entry.path or i.entry.text) not in STOCK}
            if not drop:
                continue
            text, problem = _read_text(path)
            rel = os.path.relpath(path, self.etc_dir)
            if text is None:
                edits.append(Edit(path, "etc", None, None, "", notes=[problem or ""], manual=problem, etc_rel=rel))
                continue
            kept = [line for n, line in enumerate(text.splitlines(True), 1) if n not in drop]
            removed = [line.strip() for n, line in enumerate(text.splitlines(True), 1) if n in drop]
            if path != paths_file and not any(line.strip() for line in kept):
                new, ops = None, [f"system paths: removed {path}: every line names a removed prefix"]
            else:
                new, ops = "".join(kept), [f"system paths: removed {', '.join(removed)} from {path}"]
            manual = f"{path} is a symlink: make this edit by hand" if os.path.islink(path) else None
            edits.append(Edit(path, "etc", text, new, unified_diff(path, text, new), ops,
                              realpath=os.path.realpath(path), manual=manual, etc_rel=rel))
        return edits

    def launchd_edit(self, gui: Sequence[str]) -> Edit | None:
        """Return the GUI PATH edit that drops the entries of removed prefixes

        The tool never runs the `launchctl config user path` command it prints; the user does.

        @param gui  the entries of the GUI PATH, as text
        @returns    the edit; None when the GUI PATH names no removed prefix
        """
        index = PrefixIndex(self.surv.instances)
        kept = []
        for text in gui:
            owner = index.owner(os.path.normpath(text)) if text.startswith("/") else None
            if owner is None or owner.prefix not in self.removed or os.path.normpath(text) in STOCK:
                kept.append(text)
        if len(kept) == len(gui):
            return None
        old, new = ":".join(gui), ":".join(kept)
        command = ["sudo", "launchctl", "config", "user", "path", new]
        return Edit(GUI_PATH, "launchd", old + "\n", new + "\n", unified_diff("GUI PATH", old + "\n", new + "\n"),
                    ["the GUI PATH names a removed prefix"], command=command,
                    manual=f"run by hand: {shlex.join(command)}")

    def edit_of(self, f: _File) -> Edit | None:
        """Return the edit of one rc file: its diff when it has operations, and its notes

        @param f  the file
        @returns  the edit; None for a file with no operation and no note
        """
        if not f.ops and not f.notes:
            return None
        new = f.text.render() if f.ops else f.text.old
        return Edit(f.path, "rc", f.text.old, new, unified_diff(f.path, f.text.old, new) if f.ops else "", list(f.ops),
                    shell=f.shell, realpath=os.path.realpath(f.path), manual=f.manual if f.ops else None,
                    notes=list(f.notes), fish=self.fish if f.shell == "fish" else None)

    def edits(self, gui: Sequence[str]) -> list[Edit]:
        """Return each rc file's edit, a note when the PATH edits cannot run, the `/etc` edits and the GUI PATH

        @param gui  the entries of the GUI PATH, as text
        @returns    the edits, in that order
        """
        self.load()
        self.rc_ops()
        general = self.order()
        out = [e for e in (self.edit_of(f) for f in self.files.values()) if e is not None]
        if general:
            out.append(Edit("shell setup", "note", None, None, "", notes=general))
        out += self.etc_edits()
        launchd = self.launchd_edit(gui)
        if launchd is not None:
            out.append(launchd)
        return out


def login_shell_of(bundle) -> str | None:
    """Return the account's login shell as the scan found it

    @param bundle  the scan, with its shell analysis or the environment it wrote
    @returns       the shell's path; None when the scan found none
    """
    if bundle.analysis is not None:
        return bundle.analysis.login_shell
    return bundle.result.environment.get("login_shell")


def _gui_texts(bundle) -> list[str]:
    """Return the entries of the GUI PATH as the scan found them

    @param bundle  the scan, with its shell analysis or the environment it wrote
    @returns       the entries as text; empty when launchd holds no PATH
    """
    if bundle.analysis is not None:
        return [e.text for e in bundle.analysis.gui_path or []]
    return [e.get("text", "") for e in bundle.result.environment.get("gui_path") or [] if isinstance(e, dict)]


def compute(bundle, surv: Survivors, home: str, environ: Mapping[str, str], *, etc_dir: str = "/etc",
            uid: int | None = None) -> list[Edit]:
    """Return the environment edits from a shell analysis over `surv.instances`, running no command

    @param bundle   the fresh scan
    @param surv     the survivor set
    @param home     the user's home
    @param environ  the environment the tool runs with
    @param etc_dir  the system directory that holds the shells' rc files and `paths`
    @param uid      whose rc files the tool may write; None for the user's
    @returns        the edits, as `_Cleanup.edits` returns them
    """
    analysis = env_shell.analyse(_ScanProbes(), home, dict(environ), surv.instances, login_shell_of(bundle),
                                 etc_dir=etc_dir)
    cleanup = _Cleanup(analysis, surv, home, environ, etc_dir=etc_dir, uid=os.getuid() if uid is None else uid)
    return cleanup.edits(_gui_texts(bundle))


# Applying -------------------------------------------------------------------------------------

@dataclass
class ApplyResult:
    """What applying the edits did, file by file"""

    written: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)   # the syntax check refused the rewrite: apply its diff by hand
    manual: list[str] = field(default_factory=list)     # never written by the tool
    failed: list[str] = field(default_factory=list)     # a write or a removal that failed

    @property
    def ok(self) -> bool:
        """Return whether every write and removal succeeded

        @returns  True when none failed
        """
        return not self.failed


def render(edit: Edit) -> list[str]:
    """Return the lines `env-cleanup` and phase 7 print for one edit

    @param edit  the edit
    @returns     its path, operations, diff and notes, then the reason it is manual
    """
    lines = [f"== {edit.path}"]
    lines += [f"   {op}" for op in edit.ops]
    lines += edit.diff.splitlines()
    lines += [f"   note: {note}" for note in edit.notes if note != edit.manual]
    if edit.manual:
        lines.append(f"   {edit.manual}")
    return lines


def _journal_write(runner, run_dir: state.RunDir, edit: Edit, path: str, content: str, *, digest: str,
                   backup: str | None, root: bool) -> None:
    """Journal a write with the SHA-256 of the content written

    @param runner   the runner, whose phase the record carries
    @param run_dir  the run directory, whose journal receives the record
    @param edit     the edit written
    @param path     the file written, the edit's path resolved
    @param content  the content written
    @param digest   the SHA-256 of that content
    @param backup   the run's copy of the file from before its first write, or None
    @param root     whether root wrote the file
    """
    phase = runner.phase if runner.phase is not None else 7
    action = Action(action_id=f"{phase}.write.{state.slug(path)}", kind="write", argv=[], sudo=root,
                    description=f"rewrite {edit.path}", dst=path, content=content)
    run_dir.journal.append({"ts": state.now_iso(), "phase": runner.phase, "action_id": action.action_id,
                            "kind": "write", "path": path, "named": edit.path, "sha256": digest, "backup": backup,
                            "root": root, "ops": list(edit.ops)})
    runner.record_result(action, True)


def _syntax_refused(runner, edit: Edit) -> bool:
    """Return whether the shell's parser rejects the rewrite while it accepts the original

    @param runner  the runner of the syntax checks
    @param edit    an rc file's edit
    @returns       True when the rewrite fails its check and the original does not
    """
    if not edit.shell or edit.new_text is None:
        return False
    if env_shell.syntax_check(runner, edit.shell, edit.new_text, fish=edit.fish, subject=edit.path) is not False:
        return False
    return env_shell.syntax_check(runner, edit.shell, edit.old_text or "", fish=edit.fish,
                                  subject=edit.path) is not False


def _apply_rc(runner, run_dir: state.RunDir, edit: Edit, result: ApplyResult) -> None:
    """Write an rc file's edit in place through its `realpath`, after the file's first-copy backup

    A rewrite the parser rejects, or a file another uid owns, is left for a hand edit.

    @param runner   the runner, whose console takes the warnings
    @param run_dir  the run directory, which keeps the backup and the journal
    @param edit     the edit
    @param result   receives the file under `written`, `rejected`, `manual` or `failed`
    """
    console = runner.console
    if _syntax_refused(runner, edit):
        result.rejected.append(edit.path)
        console.warn(f"{edit.path}: not written: the {edit.shell} parser rejects the rewrite and accepts the file "
                     "as it is; apply the diff above by hand")
        return
    real = os.path.realpath(edit.path)
    try:
        st: os.stat_result | None = os.stat(real)
    except FileNotFoundError:
        st = None
    if st is not None and st.st_uid != os.getuid():
        result.manual.append(edit.path)
        console.warn(f"{edit.path}: not written: {real} belongs to uid {st.st_uid}; apply the diff above by hand")
        return
    content = edit.new_text or ""
    try:
        backup = run_dir.backup_first_copy(real)
        if st is None:
            os.makedirs(os.path.dirname(real), exist_ok=True)
        state.write_user_file(real, content)
    except OSError as exc:
        result.failed.append(edit.path)
        console.warn(f"{edit.path}: not written: {exc.strerror or exc}")
        return
    _journal_write(runner, run_dir, edit, real, content, digest=hashlib.sha256(content.encode("utf-8")).hexdigest(),
                   backup=backup, root=False)
    result.written.append(real)


def _apply_etc(runner, run_dir: state.RunDir, edit: Edit, root_files: RootFiles, result: ApplyResult) -> None:
    """Write an `/etc` file as root through `RootFiles`, or back it up and remove it with `sudo rm`

    @param runner      the runner of `sudo rm`, whose console takes the warnings
    @param run_dir     the run directory, which keeps the report's copy and the journal
    @param edit        the edit
    @param root_files  writes and backs up files as root
    @param result      receives the file under `written`, `removed` or `failed`
    """
    console = runner.console
    real = edit.realpath or os.path.realpath(edit.path)
    phase = runner.phase if runner.phase is not None else 7
    try:
        # The report's copy under <run>/backup/etc/, taken once per file.
        run_dir.etc_copy(real, edit.etc_rel or os.path.basename(real))
        if edit.new_text is None:
            root_files.backup(real)
            action = Action(action_id=f"{phase}.remove.{state.slug(real)}", kind="command", argv=[RM, real],
                            sudo=True, description=f"remove {real} (system paths)", on_failure=OnFailure.PROBE)
            if runner.run(action).exit != 0:
                result.failed.append(edit.path)
                console.warn(f"{real}: sudo rm failed")
                return
            result.removed.append(real)
            return
        digest = root_files.write(real, edit.new_text, run_dir.path)
    except (ActionFailed, StagingError, OSError) as exc:
        result.failed.append(edit.path)
        console.warn(f"{edit.path}: not written: {exc}")
        return
    _journal_write(runner, run_dir, edit, real, edit.new_text, digest=digest, backup=None, root=True)
    result.written.append(real)


def apply(runner, run_dir: state.RunDir, edits: Sequence[Edit], root_files: RootFiles, *,
          show: bool = True) -> ApplyResult:
    """Print each edit unless `show` is false, then write every changed edit that is not manual

    A shell file is written in place through its `realpath` after its first-copy backup; `/etc` files as root.

    @param runner      the runner of the writes, whose console prints the edits
    @param run_dir     the run directory, which keeps the backups and the journal
    @param edits       the edits, as `compute` returns them
    @param root_files  writes and backs up the `/etc` files as root
    @param show        whether to print each edit first
    @returns           the files written, removed, rejected, left for a hand edit and failed
    """
    result = ApplyResult()
    for edit in edits:
        if show:
            for line in render(edit):
                runner.console.out(line)
        if edit.manual:
            result.manual.append(edit.path)
            continue
        if not edit.changed:
            continue
        if edit.kind == "etc":
            _apply_etc(runner, run_dir, edit, root_files, result)
        elif edit.kind == "rc":
            _apply_rc(runner, run_dir, edit, result)
    return result


# The command ----------------------------------------------------------------------------------

def _target_prefix(bundle, plan: Plan | None, wanted: str, host_arch: str,
                   environ: Mapping[str, str]) -> str | None:
    """Return the plan's target when its manager is the one asked for, else that manager's fresh target

    @param bundle     the fresh scan
    @param plan       the plan of the latest completed run, or None
    @param wanted     the manager asked for: brew or ports
    @param host_arch  the host's architecture
    @param environ    the environment the tool runs with
    @returns          the target's prefix; None when that manager has no target
    """
    if plan is not None and plan.target.value == wanted:
        return plan.target_prefix
    instances = bundle.result.instances
    if wanted == Manager.BREW.value:
        inst = brew_locate.choose_target(instances, host_arch, None, environ)
    else:
        try:
            inst = mp_locate.choose_target(instances, host_arch, None)
        except mp_locate.TargetRefused:
            inst = None
    return inst.prefix if inst is not None else None


def cmd_env_cleanup(ctx: Context, make_runner: Callable[[Context, state.RunDir], BaseRunner] | None = None) -> int:
    """Run `brew-ports env-cleanup [--target brew|ports] [--apply] [--yes] [--dry-run]`

    The target defaults to that of the latest run whose phase 5 completed, whose plan also records the
    instances phase 6 deleted. Without `--apply`, or with `--dry-run`, only the diffs are printed.

    @param ctx          the command context: arguments, console, state directory and environment
    @param make_runner  builds the runner from the context and the run directory; None for `command_runner`
    @returns            the exit code: 0, 2 for no target, 3 for a preflight failure, 4 when a write fails
    """
    try:
        latest = latest_completed(ctx.state)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        ctx.console.warn(f"brew-ports env-cleanup: the latest run's plan.json cannot be read: {exc}")
        return EXIT_PREFLIGHT
    plan = latest[1] if latest else None
    journal = latest[0].journal if latest else None
    wanted = ctx.args.target or (plan.target.value if plan is not None else None)
    if not wanted:
        ctx.console.warn("brew-ports env-cleanup: no run has completed phase 5; name the target with "
                         "--target brew or --target ports")
        return EXIT_USAGE
    run_dir, runner = start_run(ctx, 7, make_runner)
    with runner.signals():
        bundle = scan.build(runner, ctx.environ)
        try:
            scan.write(bundle, run_dir)
            target = _target_prefix(bundle, plan, wanted, runner.host_arch, ctx.environ)
            if target is None:
                ctx.console.warn(f"brew-ports env-cleanup: no {wanted} instance to keep on PATH was found")
                return EXIT_PREFLIGHT
            surv = survivors(bundle, plan, journal, target_prefix=target)
            for line in survivor_lines(surv):
                ctx.console.info(f"env-cleanup: {line}")
            home = ctx.environ.get("HOME") or os.path.expanduser("~")
            edits = compute(bundle, surv, home, ctx.environ)
            return _run_edits(ctx, runner, run_dir, edits)
        finally:
            bundle.close()


def _run_edits(ctx: Context, runner, run_dir: state.RunDir, edits: Sequence[Edit]) -> int:
    """Print the edits, then write them when `--apply` asks for it and the user confirms

    @param ctx      the command context
    @param runner   the runner of the writes
    @param run_dir  the run directory, which keeps the backups and the journal
    @param edits    the edits, as `compute` returns them
    @returns        0 when nothing is written or every write succeeds, 4 when one fails
    """
    for edit in edits:
        for line in render(edit):
            ctx.console.out(line)
    writable = [e for e in edits if e.changed and not e.manual]
    if not writable:
        ctx.console.info("env-cleanup: nothing to write")
        return EXIT_OK
    if not ctx.args.apply or ctx.args.dry_run:
        ctx.console.info(f"env-cleanup: nothing written (--apply writes the {len(writable)} edits above)")
        return EXIT_OK
    if not ctx.confirm(f"Write these {len(writable)} edits?", default=False):
        ctx.console.info("env-cleanup: nothing changed")
        return EXIT_OK
    if any(e.kind == "etc" for e in writable):
        runner.sudo_preflight()
    ctx.state.touch_dirty(run_dir.run_id, "env-cleanup")
    root_files = RootFiles(runner, run_dir.run_id)
    try:
        result = apply(runner, run_dir, edits, root_files, show=False)
    finally:
        root_files.remove_staging()
    for path in result.written:
        ctx.console.info(f"env-cleanup: wrote {path}")
    for path in result.removed:
        ctx.console.info(f"env-cleanup: removed {path}")
    if not result.ok:
        ctx.console.warn(f"env-cleanup: {len(result.failed)} files were not written: {', '.join(result.failed)}")
        return EXIT_ACTION
    return EXIT_OK

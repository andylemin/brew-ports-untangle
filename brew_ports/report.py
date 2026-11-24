"""Text, markdown and JSON rendering, and redaction"""

from __future__ import annotations

import contextlib
import os
import pwd
import re
import shlex
import sys
from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Any, TextIO

from . import model

EVIDENCE_LIMIT = 20                     # lines of one list a finding keeps as evidence
NAMES_SHOWN = 8                         # names of one list a sentence gives before "and N more"
ARCH_NAMES = {"arm64": "Apple Silicon", "x86_64": "Intel"}
COMMAND_OF = {model.Manager.BREW: "brew", model.Manager.PORTS: "port"}
MANAGER_NAMES = {model.Manager.BREW: "Homebrew", model.Manager.PORTS: "MacPorts"}
KIND_NOUNS = {"formula": ("formula", "formulae"), "cask": ("cask", "casks"), "port": ("port", "ports")}
SCAN_REUSED = "Using the scan taken in the last ten minutes (--rescan takes a new one)."
NOT_CHECKED = "Not checked: "           # starts the title of a finding that stands for a check that could not run
FIX_OFFER = "Fix: brew-ports doctor --fix (asks, then "     # starts the line of a fix that `doctor --fix` makes
MOVE_OUT = ("A move out of this installation still installs the replacements of its packages, but uninstalls none of "
            "them one by one. With `--delete %s`, `brew-ports plan` plans to delete the installation whole after "
            "the move.")
DISK_SNAPSHOT = ("macOS also took a local snapshot of the disk, which it keeps for about a day or until it needs the "
                 "space.")
NO_DISK_SNAPSHOT = "macOS could not take a local snapshot of the disk. `brew-ports rollback` does not need one."


# The reader's words ---------------------------------------------------------------------

def manager_name(inst: model.Instance) -> str:
    """Return the name of an installation's manager as people write it

    @param inst  an installation
    @returns     `Homebrew` or `MacPorts`
    """
    return MANAGER_NAMES[inst.manager]


def possessive(name: str) -> str:
    """Return a name as an owner

    @param name  a name
    @returns     `Homebrew's` or `MacPorts'`
    """
    return name + ("'" if name.endswith("s") else "'s")


def at(inst: model.Instance) -> str:
    """Return an installation by its manager and its location

    @param inst  an installation
    @returns     such as `MacPorts at /opt/local`
    """
    return f"{manager_name(inst)} at {inst.prefix}"


def place(inst: model.Instance) -> str:
    """Return an installation as its first mention names it: manager, version, location and machine code

    @param inst  an installation
    @returns     such as `MacPorts 2.10.5 at /opt/local (Apple Silicon)`; one whose command cannot run says so
    """
    name = f"{manager_name(inst)} {inst.version}" if inst.version else manager_name(inst)
    notes = [ARCH_NAMES[inst.arch]] if inst.arch in ARCH_NAMES else []
    if not inst.drivable:
        notes.append(f"its `{COMMAND_OF[inst.manager]}` command cannot run")
    return f"{name} at {inst.prefix}" + (f" ({', '.join(notes)})" if notes else "")


def has(found: Sequence[model.Instance], manager: str) -> str:
    """Return what follows "there is no <manager> at <path>": the installations of it that this Mac has

    @param found    its installations
    @param manager  `Homebrew` or `MacPorts`
    @returns        the rest of the sentence
    """
    if not found:
        return f": {manager} is not installed"
    return f": this Mac has {' and '.join(at(inst) for inst in found)}"


def counted(number: int, noun: str, plural: str | None = None) -> str:
    """Return a count with its noun

    @param number  how many
    @param noun    the noun for one
    @param plural  the noun for several; None adds an `s`
    @returns       such as `1 port` or `1,240 files`
    """
    return f"{number:,} {noun if number == 1 else plural or noun + 's'}"


def by_kind(kinds: Iterable[str]) -> str:
    """Return how many packages a list holds, by kind

    @param kinds  the kind of each package: `formula`, `cask` or `port`
    @returns      such as `40 formulae, 2 casks`; empty for none
    """
    counts = Counter(kinds)
    return ", ".join(counted(counts[kind], *nouns) for kind, nouns in KIND_NOUNS.items() if counts[kind])


def some(names: Iterable[str], limit: int = NAMES_SHOWN) -> str:
    """Return names as a sentence lists them: every name of a short list, else the first ones and how many more

    @param names  the names, in the order to show
    @param limit  how many a long list shows
    @returns      such as `bat, brotli, bzip2 and 88 more`
    """
    names = list(names)
    if len(names) <= limit:
        return ", ".join(names)
    return f"{', '.join(names[:limit])} and {len(names) - limit:,} more"


def series(items: Iterable[str]) -> str:
    """Return items as a sentence lists them

    @param items  the items
    @returns      such as `a, b and c`; empty for none
    """
    items = list(items)
    return f"{', '.join(items[:-1])} and {items[-1]}" if len(items) > 1 else "".join(items)


def unsaved(count: int) -> str:
    """Return how much of the undo record could not be saved, and where each part is named

    @param count  how many parts were not saved
    @returns      the line
    """
    return (f"{counted(count, 'part')} of that record could not be saved: snapshot/notes.txt in the run folder "
            f"{'names it' if count == 1 else 'lists them'}.")


def offered(does: str) -> str:
    """Return the line of a fix that `doctor --fix` makes, for a finding whose commands would tell the reader little

    @param does  what `doctor --fix` does once the user agrees, such as `saves the file, then deletes it`
    @returns     the line, which a finding carries as a note
    """
    return f"{FIX_OFFER}{does})"


def tilde(path: str, home: str | None = None) -> str:
    """Return a path with the home folder written as `~`, for prose; a command to copy keeps the full path

    @param path  a path
    @param home  the home folder; None for the user's own
    @returns     the path, shortened when it lies in the home folder
    """
    home = (home if home is not None else os.path.expanduser("~")).rstrip("/")
    if home and (path == home or path.startswith(home + "/")):
        return "~" + path[len(home):]
    return path


def _on_path(program: str, path: str) -> bool:
    """Return whether a program's bare name, typed in a shell with this PATH, runs that program

    @param program  the program's absolute path
    @param path     a PATH value
    @returns        True when the first PATH folder that holds an executable of that name holds this file
    """
    name = os.path.basename(program)
    for folder in path.split(os.pathsep):
        candidate = os.path.join(folder or ".", name)
        try:
            if os.path.isfile(candidate) and os.stat(candidate).st_mode & 0o111:
                return os.path.samefile(candidate, program)
        except OSError:
            return False
    return False


def typed(argv: Sequence[str], sudo: bool = False, path: str | None = None, *, intel: bool = False) -> str:
    """Return a command as the user would type it

    The `arch` wrapper and sudo's own options are left out. A program is given by its bare name when typing
    that name runs the same file, else by its full path: with two Homebrews, only one of them is `brew`.

    @param argv   the command, with or without `sudo` and the `arch` wrapper in front
    @param sudo   whether the command runs under sudo although `argv` does not start with it
    @param path   the PATH that decides the bare names; None for the tool's own
    @param intel  keep an `arch -x86_64` wrapper: a command that the user is to run needs it as brew-ports does
    @returns      the shell-quoted command
    """
    words = list(argv)
    if words and os.path.basename(words[0]) == "sudo":
        sudo = True
        words = words[1:]
        while words and words[0].startswith("-"):
            if words.pop(0) == "--":
                break
    wrapper: list[str] = []
    if len(words) > 2 and os.path.basename(words[0]) == "arch" and words[1].startswith("-"):
        wrapper = ["arch", words[1]] if intel and words[1] == "-x86_64" else []
        words = words[2:]
    if words and os.path.isabs(words[0]) and _on_path(words[0], os.environ.get("PATH", "") if path is None else path):
        words[0] = os.path.basename(words[0])
    return shlex.join((["sudo"] if sudo else []) + wrapper + words)


def cut(text: str, width: int) -> str:
    """Return a command cut at a word when it is longer than a line shows

    @param text   the command
    @param width  how many characters a command may have
    @returns      the command; a cut one ends with how many words were left out and what shows them
    """
    if len(text) <= width:
        return text
    words = text[:width].rsplit(" ", 1)[0]
    return f"{words} ... ({counted(len(text.split()) - len(words.split()), 'more word')}; --verbose shows all)"


class Redactor:
    """Replace the home directory and the login name in text

    The home directory, also `%`-joined as in backup names, becomes `~` as a whole path component; the
    login name becomes `<user>` after `USER=`, `LOGNAME=` and in any other `/Users/` or `%Users%` component.
    """

    def __init__(self, home: str | None = None, user: str | None = None) -> None:
        """Build the patterns for one home directory and login name

        @param home  the home directory; None for the user's own
        @param user  the login name; None for the user's own, an empty string for none
        """
        self.home = (home if home is not None else os.path.expanduser("~")).rstrip("/")
        if user is None:
            try:
                user = pwd.getpwuid(os.getuid()).pw_name
            except KeyError:
                user = os.environ.get("USER", "")
        self.user = user or ""
        patterns = []
        if self.home and self.home != "/":
            patterns.append((re.compile(r"(?<!\w)" + re.escape(self.home) + r"(?![\w-])", re.MULTILINE), "~"))
            form = self.home.replace("/", "%")
            patterns.append((re.compile(r"(?<!\w)" + re.escape(form) + r"(?![\w-])", re.MULTILINE), "~"))
        if self.user:
            name = re.escape(self.user)
            patterns.append((re.compile(r"(?<=USER=)" + name + r"(?![\w.-])"), "<user>"))
            patterns.append((re.compile(r"(?<=LOGNAME=)" + name + r"(?![\w.-])"), "<user>"))
            patterns.append((re.compile(r"(?<=/Users/)" + name + r"(?![\w.-])"), "<user>"))
            patterns.append((re.compile(r"(?<=%Users%)" + name + r"(?![\w.-])"), "<user>"))
        self._patterns = patterns

    def __call__(self, text: str) -> str:
        """Return text with the home directory and the login name replaced

        @param text  any text
        @returns     the redacted text
        """
        for pattern, repl in self._patterns:
            text = pattern.sub(repl, text)
        return text


def _identity(text: str) -> str:
    """Return text unchanged: the redaction of a console that does not redact

    @param text  any text
    @returns     the same text
    """
    return text


class Console:
    """Terminal output with quiet and verbose levels and optional redaction, silent after a hang-up or broken pipe"""

    def __init__(self, *, stream: TextIO | None = None, err: TextIO | None = None, quiet: bool = False,
                 verbose: bool = False, redact: bool = False, redactor: Redactor | None = None) -> None:
        """Start a console on two streams

        @param stream    receives the output and the progress lines; None for standard output
        @param err       receives the warnings and the escalated commands; None for standard error
        @param quiet     print neither the progress lines nor the detail lines
        @param verbose   print the detail lines too
        @param redact    pass every line through `redactor` before it is written
        @param redactor  the redactor; None for a default one
        """
        self.stream = stream if stream is not None else sys.stdout
        self.err = err if err is not None else sys.stderr
        self.quiet = quiet
        self.verbose = verbose
        self.silenced = False
        self.echo = True         # print each escalated command before it runs; `apply` prints it with its result
        self.json_mode = False   # with --json, stdout carries the JSON alone and progress goes to stderr
        self.activity: Any = None   # the `progress.Activity` drawn on the terminal, which each write clears first
        self._redact = (redactor or Redactor()) if redact else _identity

    def redacted(self, text: str) -> str:
        """Return a line as the console would print it

        @param text  the line
        @returns     the line, redacted under `--redact`
        """
        return self._redact(text)

    def _write(self, stream: TextIO, text: str) -> None:
        """Write one line, redacted when asked; a failed write silences the console

        @param stream  the stream to write to
        @param text    the line, without its newline
        """
        if self.silenced:
            return
        try:
            with self.activity.hidden() if self.activity is not None else contextlib.nullcontext():
                stream.write(self._redact(text) + "\n")
                stream.flush()
        except (BrokenPipeError, OSError):
            self.silenced = True

    def out(self, text: str = "") -> None:
        """Print a line of output

        @param text  the line; empty for a blank line
        """
        self._write(self.stream, text)

    def info(self, text: str) -> None:
        """Print a progress line unless quiet; it goes to the error stream in JSON mode

        @param text  the line
        """
        if not self.quiet:
            self._write(self.err if self.json_mode else self.stream, text)

    def detail(self, text: str) -> None:
        """Print a detail line when verbose and not quiet; it goes to the error stream in JSON mode

        @param text  the line
        """
        if self.verbose and not self.quiet:
            self._write(self.err if self.json_mode else self.stream, text)

    def warn(self, text: str) -> None:
        """Print a warning on the error stream, even when quiet

        @param text  the warning
        """
        self._write(self.err, text)

    def error(self, text: str) -> None:
        """Print an error on the error stream, even when quiet, under the tool's name

        @param text  what went wrong and what to run or change
        """
        self._write(self.err, f"brew-ports: {text}")

    def command(self, argv: Sequence[str]) -> None:
        """Print an escalated command before it runs, unless the command's own lines show it; `--verbose` always does

        @param argv  the whole command, `sudo` included
        """
        if self.echo or self.verbose:
            self._write(self.err, "+ " + shlex.join(list(argv)))

    def json(self, obj: Any) -> None:
        """Print a value as JSON on the output stream

        @param obj  a dataclass, or any value `model.to_json` accepts
        """
        self._write(self.stream, model.to_json(obj))


def table(rows: Iterable[Sequence[Any]], headers: Sequence[str]) -> list[str]:
    """Format rows as a plain-text table with one space-padded column per header

    @param rows     the rows; each cell is printed with `str`
    @param headers  the column headers
    @returns        the header line, a dashed rule and one line per row, without trailing spaces
    """
    data = [[str(c) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in data:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for row in data:
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
    return lines


def limited(lines: Sequence[str], limit: int = EVIDENCE_LIMIT) -> list[str]:
    """Return the first lines of a list, then a count of the rest when there are more

    @param lines  the lines
    @param limit  how many lines to keep
    @returns      at most `limit` lines, then an `... and N more` line when some were dropped
    """
    lines = list(lines)
    if len(lines) <= limit:
        return lines
    return lines[:limit] + [f"... and {len(lines) - limit} more"]


def render_system(system: dict) -> list[str]:
    """Format the system facts of a scan, one sorted key per line

    @param system  the system section of scan.json
    @returns       a `System` heading, then one indented line per fact
    """
    lines = ["System"]
    for key in sorted(system):
        lines.append(f"  {key:22} {system[key]}")
    return lines


def write_markdown(path: str, lines: Iterable[str], redactor: Redactor | None = None) -> None:
    """Write lines to a markdown report, always redacted

    @param path      the report file
    @param lines     the report's lines, without newlines
    @param redactor  the redactor; None for a default one
    """
    red = redactor or Redactor()
    with open(path, "w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(red(line) + "\n")

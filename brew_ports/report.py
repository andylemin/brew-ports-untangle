"""Text, markdown and JSON rendering, and redaction"""

from __future__ import annotations

import contextlib
import os
import pwd
import re
import shlex
import sys
from collections.abc import Iterable, Sequence
from typing import Any, TextIO

from . import model

EVIDENCE_LIMIT = 20                     # lines of one list a finding keeps as evidence


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

    def command(self, argv: Sequence[str]) -> None:
        """Print an escalated command before it runs

        @param argv  the whole command, `sudo` included
        """
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

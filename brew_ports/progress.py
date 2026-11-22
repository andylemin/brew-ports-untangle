"""The activity line: the step a command is in, the program it waits for or what it has counted, and the step's age

On a terminal the line sits below the output, and a ticker thread redraws it in place ten times a second, so it
moves through a long command and through the tool's own work between commands. Every console write clears it
first, a prompt holds it off, and it is gone when the command ends. Without a terminal, with `--quiet`, or with
the output piped to another program, nothing is drawn and every function here does nothing.
"""

from __future__ import annotations

import contextlib
import os
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from typing import Any, TextIO

TICK_S = 0.1                       # the ticker's redraw interval
CLEAR = "\r\x1b[K"                 # back to the start of the line, then erase to its end
FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
ASCII_FRAMES = "|/-\\"


def age(seconds: float) -> str:
    """Return a duration as the line shows it

    @param seconds  the duration
    @returns        `12 s` below a minute, else `1:05`
    """
    whole = int(seconds)
    return f"{whole} s" if whole < 60 else f"{whole // 60}:{whole % 60:02d}"


def _columns(stream: TextIO) -> int:
    """Return the width of the terminal a stream writes to

    @param stream  the stream
    @returns       its columns; 80 when the stream has no terminal size, or a terminal reports none
    """
    try:
        return os.get_terminal_size(stream.fileno()).columns or 80
    except (AttributeError, OSError, ValueError):
        return 80


class Activity:
    """The activity line of one command, which the console clears before each write"""

    current: Activity | None = None   # the line that `step`, `counting`, `count`, `running` and `held` act on

    def __init__(self, stream: TextIO, redact: Callable[[str], str] = str,
                 clock: Callable[[], float] = time.monotonic, columns: Callable[[], int] | None = None) -> None:
        """Prepare a line on a terminal stream; nothing is drawn before `start` or `draw`

        @param stream   the terminal the line is drawn on
        @param redact   rewrites the line as the console rewrites its output
        @param clock    the clock of the step's age
        @param columns  returns the terminal's width; None asks the stream's terminal
        """
        self.stream = stream
        self._redact = redact
        self._clock = clock
        self._width = columns or (lambda: _columns(stream))
        utf8 = (getattr(stream, "encoding", None) or "").lower().replace("-", "") == "utf8"
        self._frames = FRAMES if utf8 else ASCII_FRAMES
        self._lock = threading.RLock()
        self._frame = 0
        self._drawn = False
        self._holds = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.label = ""
        self.since = clock()
        self.command = ""          # the description of the command that runs, empty between commands
        self.unit = ""             # what `done` counts; empty when the step counts nothing
        self.done = 0
        self.total: int | None = None

    def step(self, label: str) -> None:
        """Begin a step: its label, its age from zero, and no count

        @param label  the step, such as `Homebrew /usr/local: keg files`
        """
        with self._lock:
            self.label = label
            self.since = self._clock()
            self.unit, self.done, self.total = "", 0, None

    def text(self) -> str:
        """Return the line without its spinner

        @returns  `<step>: <count>, <command> (<age>)`, without the parts that are empty
        """
        counted = ""
        if self.unit:
            counted = f"{self.done:,} of {self.total:,} {self.unit}" if self.total else f"{self.done:,} {self.unit}"
        detail = ", ".join(part for part in (counted, self.command) if part)
        line = f"{self.label}: {detail}" if detail else self.label
        return f"{line} ({age(self._clock() - self.since)})"

    def draw(self) -> None:
        """Draw the line in place with the next spinner frame, cut to the terminal's width; not while it is held"""
        with self._lock:
            if self._holds:
                return
            self._frame += 1
            line = f"{self._frames[self._frame % len(self._frames)]} {self._redact(self.text())}"
            width = max(self._width() - 1, 20)
            if len(line) > width:
                line = line[:width - 3] + "..."
            self._write(CLEAR + line)
            self._drawn = True

    def _clear(self) -> None:
        """Erase the line when one is drawn; the caller holds the lock"""
        if self._drawn:
            self._write(CLEAR)
            self._drawn = False

    def _write(self, text: str) -> None:
        """Write to the terminal; a failed write stops the ticker

        @param text  the characters, without a newline
        """
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):
            self._stop.set()

    @contextlib.contextmanager
    def hidden(self) -> Iterator[None]:
        """Erase the line and keep the ticker from drawing while the block writes other output

        @returns  a context manager; the next tick draws the line again below what the block wrote
        """
        with self._lock:
            self._clear()
            yield

    @contextlib.contextmanager
    def held(self) -> Iterator[None]:
        """Keep the line off the terminal while a prompt, or a program that asks on the terminal, waits

        @returns  a context manager; the line returns at the first tick after the block
        """
        with self._lock:
            self._clear()
            self._holds += 1
        try:
            yield
        finally:
            with self._lock:
                self._holds -= 1

    def start(self) -> None:
        """Start the ticker thread"""
        self._thread = threading.Thread(target=self._tick, name="brew-ports-activity", daemon=True)
        self._thread.start()

    def _tick(self) -> None:
        """Redraw the line every `TICK_S` until `close`"""
        while not self._stop.wait(TICK_S):
            self.draw()

    def close(self) -> None:
        """Stop the ticker and erase the line"""
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        with self._lock:
            self._clear()


def step(label: str) -> None:
    """Begin a step on the current line, when one is drawn

    @param label  the step
    """
    if Activity.current is not None:
        Activity.current.step(label)


def counting(unit: str, total: int | None = None) -> None:
    """Have the current step count objects of one kind, from zero

    @param unit   what is counted, such as `files`
    @param total  how many there are; None when that is not known
    """
    activity = Activity.current
    if activity is not None:
        activity.unit, activity.done, activity.total = unit, 0, total


def count(n: int = 1) -> None:
    """Add to the current step's count

    @param n  how many more were checked
    """
    activity = Activity.current
    if activity is not None:
        activity.done += n


@contextlib.contextmanager
def running(description: str) -> Iterator[None]:
    """Name the command a block waits for after the current step

    @param description  what the command reads or does, as the journal records it
    @returns            a context manager that removes the name when the block ends
    """
    activity = Activity.current
    if activity is None:
        yield
        return
    activity.command = description
    try:
        yield
    finally:
        activity.command = ""


@contextlib.contextmanager
def held() -> Iterator[None]:
    """Keep the current line off the terminal for the block, as a prompt needs

    @returns  a context manager
    """
    activity = Activity.current
    if activity is None:
        yield
        return
    with activity.held():
        yield


def wanted(console: Any, environ: Mapping[str, str]) -> bool:
    """Return whether a command draws the line

    @param console  the command's console
    @param environ  the environment the tool runs with, for `TERM`
    @returns        True when standard error is a terminal that redraws in place, the output is not piped to
                    another program such as a pager, and the command is not `--quiet`
    """
    if console.quiet or environ.get("TERM") == "dumb":
        return False
    try:
        if not console.err.isatty():
            return False
        mode = os.fstat(console.stream.fileno()).st_mode
    except (AttributeError, OSError, ValueError):
        return False
    return not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode))


@contextlib.contextmanager
def shown(console: Any, label: str, environ: Mapping[str, str]) -> Iterator[None]:
    """Draw the activity line of one command while the block runs, when `wanted` allows it

    @param console  the command's console; its writes clear the line while it is drawn
    @param label    the first step: the command's name
    @param environ  the environment the tool runs with
    @returns        a context manager that erases the line when the block ends
    """
    if not wanted(console, environ):
        yield
        return
    activity = Activity(console.err, console.redacted)
    activity.step(label)
    previous, Activity.current = Activity.current, activity
    console.activity = activity
    activity.start()
    try:
        yield
    finally:
        activity.close()
        console.activity = None
        Activity.current = previous

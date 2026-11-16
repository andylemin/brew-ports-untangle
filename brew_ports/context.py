"""The command context: the parsed command line, the console, the state directory and the terminal prompts"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from . import report, runner as runner_mod, state as state_mod


class Context:
    """What every subcommand receives"""

    def __init__(self, args: argparse.Namespace, console: report.Console, state: state_mod.StateDir,
                 tty: bool | None = None, environ: dict[str, str] | None = None) -> None:
        """Gather what a subcommand needs

        @param args     the parsed command line
        @param console  the console the output goes to
        @param state    the state directory
        @param tty      whether the prompts can be answered; None tests whether standard input and output are terminals
        @param environ  the environment the tool runs with; None for the process's own
        """
        self.args = args
        self.console = console
        self.state = state
        self.tty = (sys.stdin.isatty() and sys.stdout.isatty()) if tty is None else tty
        self.environ = dict(os.environ if environ is None else environ)
        self.runner: runner_mod.BaseRunner | None = None

    @property
    def yes(self) -> bool:
        """Return whether `--yes` answers the confirmations

        @returns  True when the command line holds `--yes`
        """
        return bool(getattr(self.args, "yes", False))

    def confirm(self, question: str, default: bool = False) -> bool:
        """Ask a yes/no question: `--yes` answers yes, and without a terminal the default stands

        @param question  the question, without the `[y/N]` hint
        @param default   the answer without a terminal, or for an empty reply
        @returns         the answer
        """
        if self.yes:
            return True
        if not self.tty:
            return default
        return self.ask_terminal(question, default)

    def confirm_terminal(self, question: str) -> bool:
        """Ask for a per-item answer, as for a `doctor --fix` removal, that `--yes` never gives

        @param question  the question, without the `[y/N]` hint
        @returns         the answer; no without a terminal or for an empty reply
        """
        if not self.tty:
            return False
        return self.ask_terminal(question, False)

    def ask_terminal(self, question: str, default: bool) -> bool:
        """Ask on the terminal; an empty answer or the end of input takes the default

        @param question  the question, without the hint
        @param default   the answer for an empty reply or the end of input
        @returns         True for `y` or `yes` in any case, False for any other answer, else the default
        """
        hint = " [Y/n] " if default else " [y/N] "
        try:
            answer = input(question + hint).strip().lower()
        except EOFError:
            return default
        if not answer:
            return default
        return answer in ("y", "yes")

    def choose(self, question: str, options: Sequence[str], default: str) -> str:
        """Pick one of the options; `--yes` or no terminal takes the default

        @param question  the question
        @param options   the lowercase answers it accepts; any other repeats the question
        @param default   the answer for `--yes`, without a terminal, for an empty reply or at the end of input
        @returns         the chosen option
        """
        if self.yes or not self.tty:
            return default
        prompt = f"{question} ({'/'.join(options)}) [{default}] "
        while True:
            try:
                answer = input(prompt).strip().lower()
            except EOFError:
                return default
            if not answer:
                return default
            if answer in options:
                return answer

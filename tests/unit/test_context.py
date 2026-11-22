"""Tests of the terminal questions: their one form, the answers they take and their defaults"""

import argparse
import io
import unittest
from unittest import mock

from brew_ports import report
from brew_ports.context import Context
from tests.unit.helpers import TempDirTest


class QuestionsTest(TempDirTest):
    """Tests of `confirm`, `confirm_terminal` and `choose`"""

    def context(self, yes: bool = False, tty: bool = True) -> Context:
        """Return a context on a terminal, or without one

        @param yes  whether `--yes` is given
        @param tty  whether a terminal can answer
        @returns    the context
        """
        console = report.Console(stream=io.StringIO(), err=io.StringIO())
        return Context(argparse.Namespace(yes=yes), console, self.state_dir(), tty=tty, environ={})

    def ask(self, replies, call):
        """Run a question with canned replies

        @param replies  the lines the user types, in order
        @param call     the question, as a function of nothing
        @returns        the answer, and the prompts that were shown
        """
        prompts = []
        typed = iter(replies)

        def reply(prompt):
            prompts.append(prompt)
            return next(typed)

        with mock.patch("builtins.input", reply):
            return call(), prompts

    def test_a_yes_or_no_question_ends_in_one_form(self):
        ctx = self.context()
        answer, prompts = self.ask(["y"], lambda: ctx.confirm("Uninstall jq?"))
        self.assertTrue(answer)
        self.assertEqual(prompts, ["Uninstall jq? (y/n) [n] "])
        answer, prompts = self.ask([""], lambda: ctx.ask_terminal("Go on?", True))
        self.assertTrue(answer)
        self.assertEqual(prompts, ["Go on? (y/n) [y] "])

    def test_a_choice_of_yes_and_no_is_asked_the_same_way(self):
        ctx = self.context()
        answer, prompts = self.ask(["Y"], lambda: ctx.choose("Replace it?", ("yes", "no"), "no"))
        self.assertEqual(answer, "yes")
        self.assertEqual(prompts, ["Replace it? (y/n) [n] "])
        self.assertEqual(self.ask(["no"], lambda: ctx.choose("Replace it?", ("yes", "no"), "yes"))[0], "no")

    def test_a_choice_takes_a_word_or_its_first_letter(self):
        ctx = self.context()
        answer, prompts = self.ask(["x", "d"], lambda: ctx.choose("Keep it?", ("keep", "drop"), "keep"))
        self.assertEqual(answer, "drop")
        self.assertEqual(prompts, ["Keep it? (keep/drop) [keep] "] * 2)
        self.assertEqual(self.ask([""], lambda: ctx.choose("Keep it?", ("keep", "drop"), "keep"))[0], "keep")

    def test_choices_that_share_a_first_letter_need_the_word(self):
        ctx = self.context()
        answer, prompts = self.ask(["s", "stay"], lambda: ctx.choose("Which?", ("stay", "stop"), "stay"))
        self.assertEqual(answer, "stay")
        self.assertEqual(len(prompts), 2)

    def test_yes_and_no_terminal_take_the_default_unasked(self):
        with mock.patch("builtins.input", side_effect=AssertionError("asked")):
            self.assertEqual(self.context(yes=True).choose("Keep it?", ("keep", "drop"), "keep"), "keep")
            self.assertTrue(self.context(yes=True).confirm("Go on?"))
            self.assertFalse(self.context(tty=False).confirm("Go on?"))
            self.assertFalse(self.context(yes=True, tty=False).confirm_terminal("Remove it?"))


if __name__ == "__main__":
    unittest.main()

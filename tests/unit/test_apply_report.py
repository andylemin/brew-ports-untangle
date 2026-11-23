"""The words `apply` puts around its phases: opening lines, headings and closing lines"""

import unittest

from brew_ports import apply_report, report, runner as r
from brew_ports.model import Action, Manager
from tests.unit.fixtures.executor import builders as b
from tests.unit.helpers import make_instance, make_package

INTO = "Homebrew 5.0.2 at /opt/homebrew (Apple Silicon)"


class WordsTest(unittest.TestCase):
    """A move out of MacPorts, which is uninstalled afterwards, and out of an Intel Homebrew, which stays"""

    def setUp(self):
        self.target = make_instance(Manager.BREW, "/opt/homebrew", version="5.0.2")
        ports = make_instance(Manager.PORTS, "/opt/local", version="2.10.5")
        intel = make_instance(Manager.BREW, "/usr/local", version="4.6.0", arch="x86_64")
        self.sources = [ports, intel]
        self.jq = b.mapping(make_package("jq", "port", "/opt/local"), "formula", "jq")
        self.plan = b.plan(self.target, self.sources, mappings=[self.jq], remove=["/opt/local"], removal={
            "/opt/local": [("port", "jq"), ("port", "oniguruma")],
            "/usr/local": [("formula", "wget"), ("cask-adopted", "vlc")]})

    def test_the_opening_says_what_moves_and_what_each_side_becomes(self):
        self.assertEqual(apply_report.opening(self.plan, ["/opt/local"], "/state/runs/r1", False), [
            f"Moving 1 package into {INTO}",
            "  from MacPorts 2.10.5 at /opt/local (Apple Silicon): 2 ports to uninstall, then MacPorts itself",
            "  from Homebrew 4.6.0 at /usr/local (Intel): 1 formula to uninstall; it stays installed",
            "Run folder: /state/runs/r1"])

    def test_a_dry_run_says_so_first_and_names_no_run_folder(self):
        lines = apply_report.opening(self.plan, ["/opt/local"], "/state/runs/r1", True)
        self.assertEqual(lines[0], "Dry run: nothing will change.")
        self.assertFalse([line for line in lines if line.startswith("Run folder")])

    def test_a_plan_without_replacements_does_not_say_it_moves_any(self):
        plan = b.plan(self.target, self.sources[1:], removal={"/usr/local": []})
        self.assertEqual(apply_report.opening(plan, [], "/state/runs/r1", True)[1:], [
            f"No package moves into {INTO}",
            "  from Homebrew 4.6.0 at /usr/local (Intel): nothing to uninstall; it stays installed"])

    def test_an_installation_deleted_by_path_goes_with_its_packages(self):
        plan = b.plan(self.target, self.sources[1:], mappings=[self.jq], remove=["/usr/local"])
        plan.path_removed = {"/usr/local": [("formula", "wget")]}
        self.assertEqual(apply_report.opening(plan, ["/usr/local"], "/r", True)[2],
                         "  from Homebrew 4.6.0 at /usr/local (Intel): deleted whole, with its packages")

    def test_a_resumed_run_says_where_it_continues(self):
        self.assertEqual(apply_report.continuing("r1", 5, "/state/runs/r1"), [
            "Continuing run r1 after phase 5.", "Run folder: /state/runs/r1"])
        self.assertEqual(apply_report.continuing("r1", None, "/state/runs/r1")[0], "Continuing run r1 from its start.")

    def test_headings_name_the_installations_of_phases_2_and_6(self):
        headings = [apply_report.heading(n, self.plan, ["/opt/local"]) for n in range(9)]
        self.assertEqual(headings, [
            "Phase 0  Checks before starting", "Phase 1  Save a record for undo",
            "Phase 2  Repair Homebrew at /opt/homebrew", "Phase 3  Install the replacements",
            "Phase 4  Check the replacements", "Phase 5  Uninstall the old packages",
            "Phase 6  Uninstall MacPorts at /opt/local", "Phase 7  Clean up the shell files",
            "Phase 8  Final check"])

    def test_the_closing_lines_of_a_run(self):
        self.assertEqual(apply_report.finished(self.plan, ["/opt/local"], "r1", ["edit ~/.bash_profile yourself"]), [
            "", "Finished: 1 package moved into Homebrew at /opt/homebrew; MacPorts at /opt/local uninstalled; "
                "1 formula uninstalled from Homebrew at /usr/local.",
            "For you to do:", "  edit ~/.bash_profile yourself",
            "Undo: brew-ports rollback r1   (says how to reinstall MacPorts first; run again, it puts back what was "
            "uninstalled)",
            "Report: report.md in the run folder, with every command that ran in commands.log.",
            "Next: open a new Terminal window, which finds the moved commands and reads any edited shell file."])
        kept = apply_report.finished(self.plan, [], "r1", [])
        self.assertEqual(kept[1], "Finished: 1 package moved into Homebrew at /opt/homebrew; 2 ports uninstalled from "
                                  "MacPorts at /opt/local; 1 formula uninstalled from Homebrew at /usr/local.")
        self.assertEqual(kept[2], "Undo: brew-ports rollback r1   (puts back what was uninstalled; the replacements "
                                  "stay)")
        self.assertNotIn("For you to do:", kept)

    def test_the_closing_lines_name_what_still_has_a_newer_version(self):
        lines = apply_report.finished(self.plan, [], "r1", [], (12, "brew upgrade"))
        self.assertEqual(lines[-2:], [
            "12 packages of Homebrew at /opt/homebrew have a newer version, which this move did not install. To "
            "upgrade them: brew upgrade",
            "Next: open a new Terminal window, which finds the moved commands and reads any edited shell file."])
        one = apply_report.finished(self.plan, [], "r1", [], (1, "brew upgrade"))
        self.assertEqual(one[-2], "1 package of Homebrew at /opt/homebrew has a newer version, which this move did "
                                  "not install. To upgrade it: brew upgrade")

    def test_a_run_that_ends_early_keeps_the_tasks_and_the_undo(self):
        self.assertEqual(apply_report.leftovers(self.plan, [], "r1", ["Start dbus yourself."]), [
            "For you to do:", "  Start dbus yourself.",
            "Undo: brew-ports rollback r1   (puts back what was uninstalled; the replacements stay)",
            "Report: report.md in the run folder, with every command that ran in commands.log."])
        self.assertEqual(apply_report.tasks([]), [])
        self.assertEqual(apply_report.dry_finished("plan.json", None, ["Start dbus yourself."])[2:], [
            "For you to do after the run:", "  Start dbus yourself.", "Next: brew-ports apply plan.json"])

    def test_the_preview_of_phase_6_says_what_goes_and_what_stays(self):
        def step(action_id, kind, argv, description):
            return Action(action_id=action_id, kind=kind, argv=argv, sudo=True, description=description, manual=True,
                          instance_prefix="/opt/local")
        actions = [step("6.note.x.checks", "note", [], "first `apply` checks that no package is left"),
                   step("6.archive.a", "command", ["tar", "-czf", "-", "-C", "/", "opt/local/etc"], "save it"),
                   step("6.delete.b", "command", ["rm", "-rf", "/opt/local"], "delete /opt/local"),
                   step("6.note.x.skipped.c", "note", [], "/Applications/MacPorts stays: it holds other apps"),
                   step("6.note.x.macports-user", "note", [], "the macports user and group are deleted first")]
        self.assertEqual(apply_report.preview(self.plan, actions, ["/opt/local"]), [
            "  Save in the run folder: /opt/local/etc", "  Then delete: /opt/local",
            "  /Applications/MacPorts stays: it holds other apps",
            "  The macports user and group are deleted first",
            "  This list is from the plan. It is made again when the phase runs: what is gone by then is skipped."])

    def test_the_closing_lines_of_a_dry_run(self):
        self.assertEqual(apply_report.dry_finished("my plan.json", None), [
            "", "Dry run finished: nothing was changed.", "Next: brew-ports apply 'my plan.json'"])
        self.assertEqual(apply_report.dry_finished(None, "r1")[2], "Next: brew-ports apply --resume r1")

    def test_what_a_no_and_a_missing_terminal_leave_the_user_with(self):
        self.assertEqual(apply_report.stops_here("r1"),
                         "n stops the run here; `brew-ports apply --resume r1` continues it.")
        self.assertEqual(apply_report.declined(5, "r1"), [
            "Stopped before phase 5, as you answered. Continue with: brew-ports apply --resume r1"])
        self.assertEqual(apply_report.unanswered(3, "r1"), [
            "phase 3 asks before it changes anything, and there is no terminal to ask on",
            "  Run it in a Terminal window, or answer yes to every question: brew-ports apply --resume r1 --yes"])
        self.assertEqual(apply_report.stopped_after(3, 3, "r1", False), [
            "", "Stopped after phase 3 (--stop-after 3). Continue with: brew-ports apply --resume r1"])
        self.assertEqual(apply_report.stopped_after(3, 3, "r1", True), [
            "", "Dry run stopped after phase 3 (--stop-after 3): nothing was changed."])

    def test_the_password_line_lists_what_needs_it(self):
        self.assertEqual(apply_report.password(["uninstall ports"], False),
                         "Your password is needed (sudo) to uninstall ports.")
        self.assertEqual(apply_report.password(["uninstall ports", "stop a system service", "edit /etc/paths"], True),
                         "The run will need your password (sudo) to uninstall ports, stop a system service and edit "
                         "/etc/paths.")

    def test_a_failed_command_is_named_as_typed_and_cut_when_long(self):
        result = r.Result("5.uninstall.ports", 1, None, None, typed="sudo port uninstall " + " ".join(["zlib"] * 40))
        text = apply_report.failed(result)
        self.assertTrue(text.startswith("`sudo port uninstall zlib zlib"), text)
        self.assertTrue(text.endswith("zlib ...` failed (exit 1)"), text)
        self.assertLessEqual(len(text), apply_report.ERROR_WIDTH + 30)

    def test_the_undo_record_says_how_much_is_missing(self):
        self.assertEqual(report.unsaved(1), "1 part of that record could not be saved: snapshot/notes.txt in the "
                                            "run folder names it.")
        self.assertEqual(report.unsaved(3), "3 parts of that record could not be saved: snapshot/notes.txt in "
                                            "the run folder lists them.")


if __name__ == "__main__":
    unittest.main()

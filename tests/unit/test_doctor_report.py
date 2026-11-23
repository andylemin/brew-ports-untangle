"""The report of `doctor`: its opening, its answer, the groups, a finding's lines and the closing"""

import unittest

from brew_ports import doctor, doctor_report
from brew_ports.model import Action, Blocks, Manager, Severity
from brew_ports.report import NOT_CHECKED, offered
from tests.unit.helpers import make_instance

BREW = make_instance(Manager.BREW, "/opt/homebrew", version="5.0.2")
PORTS = make_instance(Manager.PORTS, "/opt/local", version="2.10.5")
BOTH = [BREW, PORTS]


def issue(code, severity, title, subject=None, prefix=None, **kw):
    """Return a finding

    @param code      the finding's name
    @param severity  its severity
    @param title     its title
    @param subject   its subject, or None
    @param prefix    the prefix of its installation, or None
    @param kw        further fields, such as `remedies` or `blocks`
    @returns         the finding
    """
    return doctor._issue(code, severity, title, subject, prefix, **kw)


class ReportTest(unittest.TestCase):
    """The frame of the report"""

    def test_the_opening_names_what_was_checked(self):
        self.assertEqual(doctor_report.checked(BOTH), "Checked Homebrew 5.0.2 at /opt/homebrew (Apple Silicon), "
                         "MacPorts 2.10.5 at /opt/local (Apple Silicon), your shell files and your PATH.")
        self.assertEqual(doctor_report.checked([]), "Checked your shell files and your PATH. Neither Homebrew nor "
                         "MacPorts is installed on this Mac.")

    def test_no_finding_says_so_and_points_at_the_next_command(self):
        lines = doctor_report.render([], BOTH, reused=True)
        self.assertEqual(lines[1:], ["Using the scan taken in the last ten minutes (--rescan takes a new one).", "",
                                     "No problems found."])
        self.assertEqual(doctor_report.closing([], True), ["", "Next: brew-ports recommend"])
        self.assertEqual(doctor_report.closing([], False), [])

    def test_the_answer_comes_second_and_counts_the_rest(self):
        found = [issue("env-dead-path-entries", Severity.LOW, "Your PATH lists 2 folders that do not exist"),
                 issue("brew-outdated-keg", Severity.LOW, "jq has a newer version", "jq", "/opt/homebrew"),
                 issue("env-local-builds", Severity.INFO, "2 packages were built on this Mac")]
        lines = doctor_report.render(found, BOTH)
        self.assertEqual(lines[2], "Nothing stops a move. 1 thing is worth cleaning up and 1 thing matters only if "
                                   "you keep the installation it is in.")
        self.assertEqual([line for line in lines if line and not line.startswith(" ")][2:], [
            "Worth cleaning up (1)", "Only if you keep Homebrew at /opt/homebrew (1)", "For information (1)"])

    def test_what_stops_a_move_comes_first_and_says_which_move(self):
        found = [issue("env-dead-path-entries", Severity.LOW, "Your PATH lists 2 folders that do not exist"),
                 issue("ports-damaged-registry", Severity.HIGH, "MacPorts' record of installed ports cannot be read",
                       None, "/opt/local", evidence=["the file is not a database"],
                       blocks=(Blocks.UNINSTALL, Blocks.REMOVE)),
                 issue("system-running-inside-prefix", Severity.CRITICAL, "brew-ports runs from inside Homebrew")]
        lines = doctor_report.render(found, BOTH)
        self.assertEqual(lines[2], "2 things stop a move or a part of one, listed first with what each stops. 1 thing "
                                   "is worth cleaning up.")
        self.assertEqual(lines[4:10], [
            "To fix before a move (2)",
            "  MacPorts' record of installed ports cannot be read (MacPorts at /opt/local)",
            "      the file is not a database",
            "      This stops a move out of MacPorts at /opt/local and uninstalling MacPorts at /opt/local itself.",
            "  brew-ports runs from inside Homebrew",
            "      This stops every move."])
        self.assertEqual(doctor_report.closing(found, True), [
            "", "Next: fix what is listed first, then brew-ports doctor",
            "Exit status 1: something needs a fix before a move, or is broken."])
        self.assertEqual(doctor.findings_exit(found), 1)

    def test_the_answer_says_what_is_stopped_when_it_is_one_thing(self):
        into = [issue("ports-built-for-other-os", Severity.HIGH, f"{name} was built for another macOS", name,
                      "/opt/local", blocks=(Blocks.TARGET,)) for name in ("a", "b")]
        by_prefix = doctor_report.known(BOTH)
        self.assertEqual(doctor_report.stops_what(into, by_prefix),
                         "2 things stop a move into MacPorts at /opt/local, listed first.")
        self.assertEqual(doctor_report.stops_what(into[:1], by_prefix),
                         "1 thing stops a move into MacPorts at /opt/local, listed first.")
        every = [issue("system-running-inside-prefix", Severity.CRITICAL, "brew-ports runs from inside Homebrew")]
        self.assertEqual(doctor_report.stops_what(every, by_prefix), "1 thing stops every move, listed first.")
        self.assertEqual(doctor_report.stops_what([], by_prefix), "Nothing stops a move.")

    def test_only_what_stops_a_move_or_is_broken_gives_exit_1(self):
        low = [issue("env-dead-path-entries", Severity.LOW, "x"), issue("env-shadowed-commands", Severity.MEDIUM, "y")]
        self.assertEqual(doctor.findings_exit(low), 0)
        self.assertEqual(doctor.findings_exit(low + [issue("env-login-shell", Severity.HIGH, "z")]), 1)
        self.assertEqual(doctor_report.closing(low, True), ["", "Next: brew-ports recommend"])

    def test_checks_that_could_not_run_are_listed_last(self):
        unrun = "How much disk space MacPorts at /opt/local uses: `du` gave no sizes"
        lines = doctor_report.render([], BOTH, [unrun])
        self.assertEqual(lines[-2:], ["Checks that could not run", "  " + unrun])

    def test_what_the_scan_noted_is_printed_only_when_verbose(self):
        noted = ["/opt/local: no PortIndex"]
        self.assertNotIn("  /opt/local: no PortIndex", doctor_report.render([], BOTH, scan_notes=noted))
        self.assertEqual(doctor_report.render([], BOTH, scan_notes=noted, verbose=True)[-3:],
                         ["", "Notes from the scan", "  /opt/local: no PortIndex"])

    def test_a_check_that_did_not_run_is_no_finding(self):
        unrun = issue("brew-outdated-keg", Severity.INFO, NOT_CHECKED + "which packages have a newer version", None,
                      "/opt/homebrew", evidence=["`brew info` failed there, so `brew outdated` was not run"])
        lines = doctor_report.render([unrun], BOTH, ["another check: why it did not run"])
        self.assertEqual(lines[2:], [
            "No problems found.", "", "Checks that could not run",
            "  Which packages have a newer version (Homebrew at /opt/homebrew)",
            "      `brew info` failed there, so `brew outdated` was not run",
            "  another check: why it did not run"])
        self.assertEqual((doctor_report.groups([unrun], doctor_report.known(BOTH)), doctor.findings_exit([unrun])),
                         ([], 0))

    def test_a_mac_with_one_installation_does_not_name_it(self):
        found = [issue("brew-outdated-keg", Severity.LOW, "jq has a newer version", "jq", "/opt/homebrew"),
                 issue("brew-broken-linkage", Severity.HIGH, "jq loads libraries that are missing", "jq",
                       "/opt/homebrew")]
        lines = doctor_report.render(found, [BREW])
        self.assertEqual(lines[2:], ["Nothing stops a move. 1 thing is broken or at risk and 1 thing is worth "
                                     "cleaning up.",
                                     "", "Broken or at risk (1)", "  jq loads libraries that are missing",
                                     "", "Worth cleaning up (1)", "  jq has a newer version"])
        # With a second installation, each finding says where it is: by its group's heading, or after its title.
        both = doctor_report.render(found, BOTH)
        self.assertEqual([line for line in both if "jq" in line or "keep" in line][1:], [
            "  jq loads libraries that are missing (Homebrew at /opt/homebrew)",
            "Only if you keep Homebrew at /opt/homebrew (1)", "  jq has a newer version"])

    def test_a_finding_that_asks_nothing_is_information(self):
        nothing = doctor.note("brew-several-versions", "node", "Nothing to do: node is pinned, so every version stays.")
        kept = issue("brew-several-versions", Severity.LOW, "node has 2 versions installed", "node", "/opt/homebrew",
                     remedies=[nothing])
        fix = doctor.note("brew-several-versions", "jq", "Fix: delete it yourself.")
        fixable = issue("brew-several-versions", Severity.LOW, "jq has 2 versions installed", "jq", "/opt/homebrew",
                        remedies=[fix])
        lines = doctor_report.render([kept, fixable], [BREW])
        self.assertEqual(lines[2:], ["Nothing stops a move. 1 thing is worth cleaning up.",
                                     "", "Worth cleaning up (1)", "  jq has 2 versions installed",
                                     "      Fix: delete it yourself.",
                                     "", "For information (1)", "  node has 2 versions installed",
                                     "      Nothing to do: node is pinned, so every version stays."])
        # A finding that is broken keeps its group, whatever its lines say.
        broken = issue("brew-x", Severity.HIGH, "t", "jq", "/opt/homebrew", remedies=[nothing])
        self.assertEqual(doctor_report.heading(broken, doctor_report.known([BREW])), "Broken or at risk")


class FindingTest(unittest.TestCase):
    """The lines of one finding and of several findings of one kind"""

    def test_the_fix_lines_say_who_runs_what(self):
        command = doctor.manual("brew-x", "jq", "run", ["/x/brew", "reinstall", "jq"], "")
        command.manual = False
        by_hand = doctor.manual("brew-x", "jq", "manual", ["/x/brew", "link", "--overwrite", "--dry-run", "jq"],
                                "If `brew link` reports conflicting files, list them")
        note = doctor.note("brew-x", "jq", "Nothing to do while you keep Homebrew.")
        asked = issue("brew-x", Severity.LOW, "t", "jq", "/opt/homebrew", remedies=[command, by_hand, note],
                      confirm_each=True)
        self.assertEqual(doctor_report.fix_lines(asked), [
            "Fix: brew-ports doctor --fix (asks, then runs `/x/brew reinstall jq`)",
            "If `brew link` reports conflicting files, list them: /x/brew link --overwrite --dry-run jq",
            "Nothing to do while you keep Homebrew."])
        # A command that `doctor --fix` does not offer is the user's to run.
        plain = issue("brew-x", Severity.LOW, "t", "jq", "/opt/homebrew", remedies=[command])
        self.assertEqual(doctor_report.fix_lines(plain), ["Fix: /x/brew reinstall jq"])
        self.assertEqual((doctor_report.fixable([asked]), doctor_report.fixable([plain])), (1, 0))

    def test_evidence_is_cut_unless_verbose(self):
        found = issue("env-x", Severity.LOW, "A title", evidence=[f"line {n}" for n in range(5)])
        self.assertEqual(doctor_report.finding(found, {}), [
            "  A title", "      line 0", "      line 1", "      line 2",
            "      and 2 more lines (--verbose shows them)"])
        whole = doctor_report.finding(found, {}, verbose=True)
        self.assertEqual((whole[0], len(whole)), ("  A title   [env-x]", 6))

    def test_several_findings_of_one_kind_print_as_one(self):
        found = [issue("brew-pinned-formula", Severity.INFO, f"{name} is pinned", name, "/opt/homebrew",
                       remedies=[doctor.note("brew-pinned-formula", name, "Nothing to do.")])
                 for name in ("jq", "wget")]
        lines = doctor_report.render(found, BOTH)
        self.assertEqual(lines[4:], [
            "Only if you keep Homebrew at /opt/homebrew (2)",
            "  2 formulae are pinned, so Homebrew does not upgrade them: jq, wget",
            "      Nothing to do."])
        each = doctor_report.render(found, BOTH, verbose=True)
        self.assertIn("  jq is pinned   [brew-pinned-formula]", each)

    @staticmethod
    def delete(path):
        """Return a command that `doctor --fix` runs: the deletion of a path

        @param path  the path
        @returns     the action
        """
        return Action(action_id="doctor.x." + path, kind="command", argv=["/nowhere/rm", "-rf", path], sudo=False,
                      description="")

    def test_what_fix_offers_and_what_it_does_not_are_two_lines(self):
        cellar = "/opt/homebrew/Cellar"
        found = [issue("brew-several-versions", Severity.LOW, f"Version {v} of {name} is installed but not in use",
                       f"{cellar}/{name}/{v}", "/opt/homebrew", confirm_each=True,
                       remedies=[self.delete(f"{cellar}/{name}/{v}")])
                 for name, v in (("jq", "1.5"), ("jq", "1.6"), ("wget", "1.0"))]
        found += [issue("brew-several-versions", Severity.LOW, f"{name} has 2 versions installed", name,
                        "/opt/homebrew", remedies=[doctor.note("brew-several-versions", name, "Nothing to do.")])
                  for name in ("node", "vim")]
        self.assertEqual(doctor_report.render(found, BOTH)[5:], [
            "  2 formulae have more than one version installed: jq, wget",
            "      Fix: brew-ports doctor --fix (asks about each)",
            "  2 formulae have more than one version installed: node, vim",
            "      Nothing to do."])
        # Two findings about one formula count that formula once, in the singular.
        self.assertEqual(doctor_report.several(found[:2]), [
            "  1 formula has more than one version installed: jq",
            "      Fix: brew-ports doctor --fix (asks about each)"])

    def test_a_fix_said_in_words_replaces_its_commands(self):
        says = "saves the file in the run folder, then deletes it"
        found = [issue("ports-unregistered-file", Severity.MEDIUM, f"No port installed {path}", path, "/opt/local",
                       confirm_each=True, remedies=[doctor.note("ports-unregistered-file", path, offered(says)),
                                                    self.delete(path)])
                 for path in ("/opt/local/bin/a", "/opt/local/bin/b")]
        self.assertEqual((doctor_report.fix_lines(found[0]), doctor_report.does(found[0])),
                         ([f"Fix: brew-ports doctor --fix (asks, then {says})"], says))
        self.assertEqual(doctor_report.render(found, BOTH)[5:], [
            "  2 files were not installed by any port: bin/a, bin/b",
            f"      Fix: brew-ports doctor --fix (asks about each, then {says})"])


class FixTest(unittest.TestCase):
    """What `doctor --fix` says: what it offers, what a yes and a no do, and what it did"""

    def setUp(self):
        run = Action(action_id="doctor.brew-x.jq.reinstall", kind="command", argv=["/x/brew", "reinstall", "jq"],
                     sudo=False, description="")
        self.reinstall = issue("brew-x", Severity.HIGH, "jq has no install record", "jq", "/opt/homebrew",
                               remedies=[run, doctor.note("brew-x", "jq", "A note to know.")], confirm_each=True)
        self.by_prefix = doctor_report.known(BOTH)

    def test_the_opening_says_what_is_offered_and_what_it_needs(self):
        every = "`brew-ports doctor` lists everything that was found."
        yes = ("--yes answers for you, except where a fix uninstalls a package or one of its versions, or deletes a "
               "cask's record or a stray file: that takes your own answer on a terminal.")
        self.assertEqual(doctor_report.fix_opening(1, True, False, False), [
            f"doctor --fix offers 1 fix. It asks before it changes anything. {every}",
            "It needs your password (sudo)."])
        self.assertEqual(doctor_report.fix_opening(3, True, False, True), [
            f"doctor --fix offers 3 fixes. {yes} {every}", "Some of them need your password (sudo)."])
        # A dry run says the same of the answers, and asks for no password.
        self.assertEqual(doctor_report.fix_opening(3, True, True, True), [
            f"doctor --fix offers 3 fixes. {yes} {every}"])
        self.assertEqual(doctor_report.fix_opening(2, False, False, False, tty=False), [
            "doctor --fix offers 2 fixes. There is no terminal to ask on, so it makes none of them: `brew-ports "
            f"doctor --fix --yes` answers for you. {every}"])

    def test_yes_answers_for_a_deleted_link_and_a_leftover_service(self):
        """What the opening says of `--yes` holds for each finding: only the named kinds take a terminal's answer"""
        answered = ("brew-broken-symlink", "brew-orphan-service", "ports-dangling-plist")
        own = ("brew-deleted-formula", "brew-several-versions", "brew-orphan-caskroom", "ports-inactive-versions",
               "ports-unrequested-leaf", "ports-unregistered-file")
        delete = FindingTest.delete("/x/y")
        for code in answered + own:
            found = issue(code, Severity.LOW, "t", "y", "/x", confirm_each=True, remedies=[delete])
            self.assertEqual(doctor.needs_terminal_answer(found), code in own, code)

    def test_the_lines_above_a_question_say_what_each_answer_does(self):
        named = "jq has no install record (Homebrew at /opt/homebrew)"
        self.assertEqual(doctor_report.offer(self.reinstall, self.by_prefix), [
            named, "  y runs `/x/brew reinstall jq`; n changes nothing.", "  A note to know."])
        self.assertEqual(doctor_report.offer(self.reinstall, self.by_prefix, ["saves a record", "stops a service"]), [
            named, "  y saves a record,", "    then stops a service,", "    then runs `/x/brew reinstall jq`.",
            "  n changes nothing.", "  A note to know."])
        self.assertEqual(doctor_report.offer(self.reinstall, self.by_prefix, ["saves a record"], "dry"), [
            named, "  doctor --fix asks, then saves a record, then runs `/x/brew reinstall jq`.", "  A note to know."])
        # In a dry run with --yes, a fix that --yes answers for is made without a question.
        self.assertEqual(doctor_report.offer(self.reinstall, self.by_prefix, how="dry-yes"), [
            named, "  doctor --fix runs `/x/brew reinstall jq`.", "  A note to know."])
        self.assertEqual(doctor_report.offer(self.reinstall, self.by_prefix, how="run"), [named, "  A note to know."])

    def test_fixes_that_take_one_answer_are_listed_with_what_runs(self):
        one = doctor_report.known([BREW])
        listed = ["  jq has no install record", "      runs `/x/brew reinstall jq`"] * 2
        self.assertEqual(doctor_report.together([self.reinstall] * 2, one, True),
                         ["These 2 fixes take one answer:"] + listed + ["  y makes them; n changes nothing."])
        self.assertEqual(doctor_report.together([self.reinstall] * 2, one, False, True),
                         ["With --yes, these 2 fixes are made without a question:"] + listed)

    def test_the_last_lines_say_what_was_done_and_what_is_next(self):
        undo = "If a fix of this run uninstalled something you want back: brew-ports rollback 20261123-1"
        self.assertEqual(doctor_report.fix_closing(2, [], "20261123-1"), [
            "", "Made 2 fixes.", undo, "Next: brew-ports doctor   (it checks again and lists what is left)"])
        self.assertEqual(doctor_report.fix_closing(0, [self.reinstall], None), [
            "", "Made no fix.", "Next: brew-ports doctor   (it lists what was found)",
            "Exit status 1: something needs a fix before a move, or is broken."])
        stopped = ["  Its whole output is in the folder `out` of the run folder, ~/runs/1.",
                   "  The fix made before it stays. Fix the cause, then run `brew-ports doctor --fix` again."]
        self.assertEqual(doctor_report.fix_stopped("~/runs/1", 1), stopped)
        self.assertEqual(doctor_report.fix_stopped("~/runs/1", 1, "20261123-1"), stopped + ["  " + undo])

    def test_env_cleanup_is_the_fix_only_for_what_it_keeps(self):
        by_hand = "Fix, if this is the Homebrew you keep: put %s/bin in front of /usr/bin in your shell's login file."
        found = [issue("brew-path-order", Severity.LOW, "t", prefix + "/bin", prefix,
                       remedies=[doctor.note("brew-path-order", prefix, by_hand % prefix)])
                 for prefix in ("/opt/homebrew", "/usr/local")]
        doctor.path_fixes(found, {"brew": "/opt/homebrew", "ports": None})
        self.assertEqual([doctor_report.fix_lines(i) for i in found], [
            ["Fix, if this is the Homebrew you keep: `brew-ports env-cleanup --target brew --apply` puts it in front "
             "of /usr/bin in your shell's login file; it shows the change and asks first."],
            [by_hand % "/usr/local"]])

    def test_a_run_that_changes_nothing_explains_exit_status_1(self):
        self.assertEqual(doctor_report.unchanged([self.reinstall]),
                         ["Exit status 1: something needs a fix before a move, or is broken."])
        self.assertEqual(doctor_report.unchanged([]), [])

    def test_a_brew_env_file_takes_the_brew_fixes_out_of_the_count(self):
        self.reinstall.remedies[0].env_profile = "brew"
        override = issue("brew-env-override", Severity.HIGH, "a brew.env file", "/etc/homebrew/brew.env",
                         "/opt/homebrew", blocks=(Blocks.ANY,))
        self.assertEqual((doctor_report.fixable([self.reinstall]), doctor_report.fixable([self.reinstall, override])),
                         (1, 0))
        # The report then says why the finding gets no fix, and `doctor --fix` names it once with the reason.
        no_fix = "No fix until the brew.env lines that `brew-ports doctor` lists are removed."
        self.assertEqual(doctor_report.fix_lines(self.reinstall, blocked=True), [no_fix, "A note to know."])
        self.assertIn("      " + no_fix, doctor_report.render([self.reinstall, override], [BREW]))
        self.assertNotIn("      " + no_fix, doctor_report.render([self.reinstall], [BREW]))
        self.assertEqual(doctor_report.not_offered([self.reinstall], doctor_report.known([BREW])), [
            "", "Not offered, because a brew.env file changes the settings that brew-ports runs `brew` with "
            "(`brew-ports doctor` lists the lines to remove):", "  jq has no install record"])
        self.assertEqual(doctor_report.not_offered([], {}), [])


if __name__ == "__main__":
    unittest.main()

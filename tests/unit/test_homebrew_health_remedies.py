"""Homebrew health remedies: the argv and flags of each variant, the removal rule, the kept kegs and the queries

The queries are `needs_terminal_answer`, `removes_package` and `verify`.
"""

import json
import os
import unittest

from brew_ports import model, runner as r, state
from brew_ports.env import linkage as lk
from brew_ports.homebrew import health, inventory, locate
from brew_ports.model import OnFailure
from tests.unit.test_homebrew_health_support import GIT_STATUS, HealthCase, fixture, service, symlink, write
from tests.unit.test_runner import QuietConsole

THIN64 = b"\xcf\xfa\xed\xfe" + b"\x0c\x00\x00\x01" + b"\x00" * 24
QUERIED = ("brew-keg-without-receipt", "brew-deleted-formula", "brew-several-versions", "brew-missing-dependency",
           "brew-broken-linkage", "brew-orphan-service", "brew-missing-app", "brew-orphan-caskroom")


def otool_section(path, refs):
    """Return the `otool -l` text of one file with `LC_LOAD_DYLIB` references

    @param path  the file
    @param refs  the libraries it loads
    @returns     the text, one load command per reference
    """
    lines = [f"{path}:"]
    for number, name in enumerate(refs):
        lines += [f"Load command {number}", "          cmd LC_LOAD_DYLIB", "      cmdsize 56",
                  f"         name {name} (offset 24)"]
    return "\n".join(lines) + "\n"


class StashTest(HealthCase):
    """The stash, patch and recovery remedies of a repository with local changes"""

    def dirty(self):
        """Give the prefix a `.git` whose `git status --porcelain` reports an untracked file"""
        os.makedirs(os.path.join(self.prefix, ".git"))
        self.responses[GIT_STATUS + ("<tmp>/opt/homebrew", "status", "--porcelain")] = r.FakeResponse(
            stdout="?? notes.txt\n")

    def test_stash_then_patch_into_the_run_directory(self):
        self.run_dir = self.state_dir().new_run()
        self.dirty()
        _, stash, patch, recover = self.only("brew-unusable-or-dirty").remedies
        self.assertEqual(stash.argv, [health.GIT, "-c", "author.name=brew-ports", "-c",
                                      "author.email=brew-ports@localhost", "-c", "committer.name=brew-ports", "-c",
                                      "committer.email=brew-ports@localhost", "-C", self.prefix, "stash", "push",
                                      "--include-untracked", "-m", "brew-ports " + self.run_dir.run_id])
        self.assertEqual((stash.env_profile, stash.sudo, stash.on_failure, stash.read_only, stash.manual),
                         ("neutral", False, OnFailure.STOP, False, False))
        expected = os.path.join(self.run_dir.path, "data-archive", state.slug(self.prefix) + ".stash.patch")
        self.assertEqual(patch.argv, [health.GIT, "-C", self.prefix, "stash", "show", "-p", "--include-untracked",
                                      "stash@{0}"])
        self.assertEqual((patch.dst, patch.read_only, patch.manual), (expected, True, False))
        self.assertEqual((recover.manual, recover.argv), (True, [health.GIT, "-C", self.prefix, "stash", "pop"]))
        fake = r.FakeRunner(default=r.FakeResponse(stdout="diff --git a/notes.txt b/notes.txt\n"),
                            console=QuietConsole(), environ={"HOME": self.home}, run_dir=self.run_dir)
        fake.run(stash)
        fake.run(patch)
        with open(expected, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "diff --git a/notes.txt b/notes.txt\n")

    def test_commands_printed_without_a_run_directory(self):
        self.dirty()
        issue = self.only("brew-unusable-or-dirty")
        self.assertTrue(all(a.manual for a in issue.remedies))
        self.assertFalse(issue.confirm_each)
        # Nothing here stands for a folder that does not exist: the stash is named without a run.
        self.assertEqual((issue.remedies[0].argv[-1], issue.remedies[1].dst), ("brew-ports", None))
        self.assertEqual([line.split(":")[0] for line in self.fixes(issue)],
                         ["Set the changes aside", "Look at them", "To get the changes back afterwards"])


class ReceiptAndRemovalTest(HealthCase):
    """The receipt-less and deleted-formula remedies: reinstall, removal, replacement notes and their limits"""

    def test_no_tab_step_for_an_unrequested_formula(self):
        self.formula("wget", receipt=False, requested=False)
        issue = self.only("brew-keg-without-receipt")
        self.assertEqual([a.argv for a in issue.remedies], [self.brew_argv("reinstall", "--formula", "wget")])

    def test_receiptless_deleted_formula_is_removed(self):
        self.formula("oldtool", receipt=False, known=False)
        issues = self.detect()
        issue = self.found("brew-keg-without-receipt", issues)[0]
        self.assertEqual([a.argv for a in issue.remedies],
                         [self.brew_argv("uninstall", "--formula", "--force", "oldtool")])
        self.assertEqual((issue.confirm_each, issue.repairs_install), (True, False))
        self.assertEqual(issue.evidence[-1], "Homebrew's package list does not have it under any name")
        self.assertTrue(health.needs_terminal_answer(issue))
        self.assertEqual(health.removes_package(issue), ("formula", "oldtool"))
        self.assertEqual(self.found("brew-deleted-formula", issues), [])

    def test_refused_formula_gets_a_replacement_note(self):
        self.formula("aescrypt", receipt=False)
        self.formulae["aescrypt"] = {"disable_args": {":because": "switched to a commercial license",
                                                      ":date": "2026-03-17", ":replacement_formula": "ccrypt"}}
        issue = self.only("brew-keg-without-receipt")
        self.assertEqual([(a.kind, a.manual) for a in issue.remedies], [("note", True)])
        self.assertEqual(self.fixes(issue), [
            "Fix: install ccrypt, which Homebrew names as its replacement, then uninstall aescrypt. A move out of "
            "this Homebrew looks up the replacement itself."])
        self.assertEqual(issue.evidence[-1], "Homebrew stopped installing it on 2026-03-17 (switched to a "
                                             "commercial license)")
        self.assertEqual((issue.confirm_each, health.needs_terminal_answer(issue), health.removes_package(issue)),
                         (False, False, None))

    def test_formula_with_data_or_a_service_stays(self):
        self.formula("oldtool", known=False)
        data = os.path.join(self.prefix, "var", "oldtool")
        os.makedirs(data)
        issue = self.only("brew-deleted-formula")
        self.assertEqual(self.fixes(issue), [
            f"brew-ports offers no fix: oldtool owns the data folder {data}. Only its own programs can read that "
            "data, and Homebrew cannot install them again."])
        self.assertFalse(issue.confirm_each)
        self.assertIsNone(health.removes_package(issue))
        os.rmdir(data)
        plist = os.path.join(self.home, "Library", "LaunchAgents", "sh.brew.oldtool.plist")
        self.services = [service("sh.brew.oldtool", plist, self.prefix, "oldtool")]
        issue = self.only("brew-deleted-formula")
        self.assertTrue(all(a.manual for a in issue.remedies))
        self.assertIn("oldtool owns the service sh.brew.oldtool.", self.fixes(issue)[0])

    def test_moved_formula_gets_its_new_home(self):
        self.formula("android-ndk", known=False)
        self.cat_kw["formula_tap_migrations"] = {"android-ndk": "homebrew/cask"}
        issue = self.only("brew-deleted-formula")
        self.assertEqual(issue.title, "android-ndk is installed, but Homebrew moved it to the tap homebrew/cask")
        self.assertEqual([(a.kind, a.manual) for a in issue.remedies], [("note", True)])
        self.assertEqual(self.fixes(issue), [
            "Fix: install android-ndk from the tap homebrew/cask, then uninstall this copy. A move out of this "
            "Homebrew looks up the replacement itself."])

    def test_fallback_catalogue_needs_brew_doctor(self):
        self.formula("oldtool", known=False)
        self.cat_kw = {"source": "taps"}
        issue = self.only("brew-deleted-formula")
        self.assertEqual(self.fixes(issue), [
            "brew-ports offers no fix: the package list read here does not record new names, so oldtool may only "
            "have been renamed, and `brew doctor` does not report it."])
        self.doctor = r.FakeResponse(exit=1, stderr=fixture("doctor-stderr.txt", PREFIX=self.prefix))
        issue = self.only("brew-deleted-formula")
        self.assertEqual([a.argv for a in issue.remedies if a.kind == "command"],
                         [self.brew_argv("uninstall", "--formula", "--force", "oldtool")])

    def test_undrivable_instance_gets_no_brew_command(self):
        self.inst.usability, self.inst.drivable = model.Usability.CANNOT_RUN, False
        self.formula("oldtool", known=False)
        self.formula("wget", receipt=False)
        self.formula("unlinked", linked=False)
        issues = self.detect()
        for code in ("brew-keg-without-receipt", "brew-deleted-formula", "brew-unlinked-keg"):
            with self.subTest(code=code):
                issue = self.found(code, issues)[0]
                self.assertEqual((issue.confirm_each, issue.repairs_install), (False, False))
                self.assertEqual(self.fixes(issue),
                                 [f"No fix until the `brew` command of Homebrew at {self.prefix} runs."])


class KeptKegTest(HealthCase):
    """Which kegs of a formula with several versions stay, and which a remedy removes"""

    def kegs(self, name, versions):
        """Return the keg directories of some versions of a formula

        @param name      the formula's rack
        @param versions  the versions
        @returns         the paths, in the order given
        """
        return [os.path.join(self.prefix, "Cellar", name, v) for v in versions]

    def removable(self):
        """Return the kegs that the `brew-several-versions` findings offer to remove

        @returns  the subjects of the findings whose remedy is a command
        """
        return [i.subject for i in self.found("brew-several-versions", self.detect())
                if any(not a.manual for a in i.remedies)]

    def test_the_linked_keg_and_the_opt_target_both_stay(self):
        self.formula("wget", versions=("1.0", "2.0"), opt=False)
        symlink(os.path.join(self.prefix, "opt", "wget"), self.kegs("wget", ["1.0"])[0])
        issue = self.only("brew-several-versions")
        self.assertEqual((issue.subject, issue.title), ("wget", "wget has 2 versions installed: 1.0, 2.0"))
        self.assertEqual(issue.evidence, ["in use: 2.0 (linked), 1.0 (the version other formulae use)"])
        self.assertEqual(self.fixes(issue), ["Nothing to do: every version stays."])

    def test_keg_only_formula_keeps_an_older_opt_target(self):
        self.formula("openssl@3", versions=("1.0", "2.0", "3.0"), linked=False, keg_only=True, opt=False)
        symlink(os.path.join(self.prefix, "opt", "openssl@3"), self.kegs("openssl@3", ["1.0"])[0])
        self.assertEqual(self.removable(), self.kegs("openssl@3", ["2.0", "3.0"]))

    def test_without_links_the_newest_keg_stays(self):
        self.formula("wget", versions=("1.0", "2.0"), linked=False, opt=False)
        self.assertEqual(self.removable(), self.kegs("wget", ["1.0"]))

    def test_pinned_root_owned_and_running_kegs_stay(self):
        self.formula("pinned", versions=("1.0", "2.0"), pinned=True)
        self.formula("rooted", versions=("1.0", "2.0"))
        self.inv.root_owned = {"rooted": [os.path.join(self.kegs("rooted", ["1.0"])[0], "bin")]}
        self.formula("served", versions=("1.0", "2.0"))
        old = self.kegs("served", ["1.0"])[0]
        self.services = [service("sh.brew.served", self.path("agents", "sh.brew.served.plist"), self.prefix, "served",
                                 program=os.path.join(old, "bin", "served"))]
        issues = self.found("brew-several-versions", self.detect())
        self.assertEqual([i.subject for i in issues], ["pinned", "rooted", "served"])
        self.assertEqual(self.removable(), [])
        self.assertEqual(self.fixes(issues[0]), ["Nothing to do: pinned is pinned, so every version stays."])
        self.assertEqual(issues[1].evidence[-1], "1.0 stays too: files in it belong to root")
        self.assertEqual(issues[2].evidence[-1], "1.0 stays too: the service sh.brew.served runs "
                                                 f"{os.path.join(old, 'bin', 'served')} from it")


class VariantTest(HealthCase):
    """Remedy variants: a shared `/usr/local`, a cask dependency, system services and casks that need sudo"""

    def test_shared_prefix_removes_only_homebrews_links(self):
        self.inst.owned_roots = tuple(os.path.join(self.prefix, sub) for sub in locate.USR_LOCAL_SUBTREES)
        gone = symlink(os.path.join(self.prefix, "bin", "gone"), "../Cellar/gone/1.0/bin/gone")
        tex = symlink(os.path.join(self.prefix, "bin", "tex"), "/Library/TeX/texbin/tex")
        issues = {i.subject: i for i in self.found("brew-broken-symlink", self.detect())}
        self.assertEqual(sorted(issues), [gone, tex])
        self.assertEqual([a.argv for a in issues[gone].remedies], [[health.RM, gone]])
        self.assertFalse(issues[tex].confirm_each)
        self.assertEqual(self.fixes(issues[tex]), [
            f"brew-ports leaves it alone: it lies outside Homebrew's own folders in {self.prefix}, so something "
            "else may have put it there."])

    def test_missing_cask_dependency(self):
        self.inv.missing = {"sshfs-helper": ["macfuse-like"]}
        self.casks["macfuse-like"] = {}
        issue = self.only("brew-missing-dependency")
        self.assertEqual(issue.remedies[0].argv, self.brew_argv("install", "--cask", "macfuse-like"))
        self.casks["macfuse-like"] = {"raw_artifacts": [[":pkg", ["macfuse.pkg"]]]}
        issue = self.only("brew-missing-dependency")
        self.assertEqual((issue.remedies[0].manual, issue.auto_fix, issue.repairs_install), (True, False, False))
        self.assertEqual(issue.remedies[0].argv, [self.inst.binary, "install", "--cask", "macfuse-like"])

    def test_system_scope_service_and_unloaded_job(self):
        daemon = "/Library/LaunchDaemons/homebrew.mxcl.nginx.plist"
        self.services = [service("homebrew.mxcl.nginx", daemon, self.prefix, "nginx", scope="system",
                                 domain="system", loaded=True)]
        issue = self.only("brew-orphan-service")
        self.assertEqual([(a.argv, a.sudo) for a in issue.remedies], [
            (["/bin/launchctl", "bootout", "system/homebrew.mxcl.nginx"], True), ([health.RM, daemon], True)])
        self.services = [service("sh.brew.redis", self.path("agents", "sh.brew.redis.plist"), self.prefix, "redis")]
        issue = self.only("brew-orphan-service")
        self.assertEqual([(a.argv[0], a.sudo) for a in issue.remedies], [(health.RM, False)])

    def test_sudo_cask_printed_and_orphan_record_removed(self):
        self.run_dir = self.state_dir().new_run()
        self.cask("vpn", apps=("VPN.app",), privileged_uninstall=True)
        self.cask("leftover", apps=(), known=False, caskfile=False, privileged_uninstall=True)
        issues = self.detect()
        missing_app = self.found("brew-missing-app", issues)[0]
        orphan = self.found("brew-orphan-caskroom", issues)[0]
        self.assertEqual((missing_app.remedies[0].argv, missing_app.remedies[0].manual, missing_app.confirm_each),
                         ([self.inst.binary, "reinstall", "--cask", "vpn"], True, False))
        # Homebrew cannot load the orphan cask, so its uninstall artifacts never run:
        # the record goes the same way whatever the privileged flags say.
        room = os.path.join(self.prefix, "Caskroom", "leftover")
        self.assertEqual(orphan.remedies[2].argv, [health.RM, "-rf", room])
        self.assertTrue(orphan.confirm_each)
        self.assertEqual(health.removes_package(missing_app), None)


class QueryTest(HealthCase):
    """The `needs_terminal_answer` and `removes_package` queries, and their answers after a JSON round trip"""

    def scenario(self):
        """Detect one instance with a finding of each kind the queries distinguish

        @returns  the findings by code
        """
        self.formula("wget", receipt=False)
        self.formula("oldtool", known=False)
        self.formula("multi", versions=("1.0", "2.0"))
        self.inv.missing = {"wget": ["libidn2"]}
        binary = os.path.join(self.prefix, "Cellar", "wget", "1.0", "bin", "wget")
        self.linkage = {"packages": {f"{self.prefix}|formula|wget": {"broken": [binary]}},
                        "binaries": {binary: {"references": [{"name": "/gone/libx.dylib", "class": "missing"}]}}}
        self.cask("foo", apps=("Foo.app",))
        self.cask("leftover", apps=(), known=False, caskfile=False)
        self.services = [service("sh.brew.gone", self.path("agents", "sh.brew.gone.plist"), self.prefix, "gone")]
        return {i.code: i for i in self.detect()}

    def test_needs_terminal_answer(self):
        by_code = self.scenario()
        answers = {code: health.needs_terminal_answer(by_code[code]) for code in QUERIED}
        self.assertEqual(answers, dict(zip(QUERIED, [False, True, True, False, False, False, False, True])))

    def test_removes_package(self):
        # A doctor --fix run has a run directory, which the orphan Caskroom archive needs.
        self.run_dir = state.StateDir(self.path("state")).new_run()
        by_code = self.scenario()
        removed = {code: health.removes_package(by_code[code]) for code in QUERIED}
        self.assertEqual(removed, dict(zip(QUERIED, [("formula", "wget"), ("formula", "oldtool"), None, None,
                                                     ("formula", "wget"), None, ("cask", "foo"),
                                                     ("cask", "leftover")])))

    def test_answers_survive_doctor_json(self):
        for issue in self.scenario().values():
            back = model.from_json(model.Issue, model.to_json(issue))
            with self.subTest(code=issue.code):
                self.assertEqual(back, issue)
                self.assertEqual((health.needs_terminal_answer(back), health.removes_package(back)),
                                 (health.needs_terminal_answer(issue), health.removes_package(issue)))

    def test_env_override_names_its_instance(self):
        self.formula("wget", receipt=False)
        self.inv.brew_env = [locate.EnvLine("/etc/homebrew/brew.env", 1, "HOMEBREW_NO_SUDO", "")]
        issues = self.detect()
        override = self.found("brew-env-override", issues)[0]
        receiptless = self.found("brew-keg-without-receipt", issues)[0]
        self.assertEqual(override.instance_prefix, self.prefix)
        self.assertEqual({a.env_profile for a in receiptless.remedies}, {"brew"})
        self.assertEqual({a.instance_prefix for a in receiptless.remedies}, {self.prefix})


class VerifyTest(HealthCase):
    """The `verify` checks after a reinstall: the receipt, `installed_on_request` and the linkage"""

    def reinstalled(self, issue, receipt):
        """Stand in for the remedy: a fresh keg that `opt/<f>` names

        @param issue    the finding whose formula is reinstalled
        @param receipt  the receipt the keg gets, or None for none
        @returns        the keg's path
        """
        keg = os.path.join(self.prefix, "Cellar", issue.subject, "9.9")
        os.makedirs(keg)
        if receipt is not None:
            write(os.path.join(keg, inventory.RECEIPT), json.dumps(receipt))
        os.unlink(os.path.join(self.prefix, "opt", issue.subject))
        symlink(os.path.join(self.prefix, "opt", issue.subject), keg)
        return keg

    def test_receipt_and_installed_on_request(self):
        self.formula("wget", receipt=False)
        issue = self.only("brew-keg-without-receipt")
        keg = self.reinstalled(issue, {"installed_on_request": False})
        self.assertIs(health.verify(issue, self.runner(), self.bundle()), False)
        write(os.path.join(keg, inventory.RECEIPT), json.dumps({"installed_on_request": True}))
        self.assertIs(health.verify(issue, self.runner(), self.bundle()), True)

    def test_receipt_needed_and_request_only_with_tab(self):
        self.formula("wget", receipt=False)
        issue = self.only("brew-keg-without-receipt")
        keg = self.reinstalled(issue, None)
        self.assertIs(health.verify(issue, self.runner(), self.bundle()), False)
        write(os.path.join(keg, inventory.RECEIPT), json.dumps({"installed_on_request": False}))
        untabbed = model.from_json(model.Issue, model.to_json(issue))
        untabbed.remedies = untabbed.remedies[:1]
        self.assertIs(health.verify(untabbed, self.runner(), self.bundle()), True)
        self.assertIs(health.verify(issue, self.runner(), self.bundle()), False)

    def test_linkage_scan_of_the_reinstalled_keg(self):
        self.formula("wget")
        binary = os.path.join(self.prefix, "Cellar", "wget", "1.0", "bin", "wget")
        self.linkage = {"packages": {f"{self.prefix}|formula|wget": {"broken": [binary]}},
                        "binaries": {binary: {"references": [{"name": "/gone/libx.dylib", "class": "missing"}]}}}
        issue = self.only("brew-broken-linkage")
        keg = self.reinstalled(issue, {"installed_on_request": True})
        tool = os.path.join(keg, "bin", "wget")
        lib = os.path.join(keg, "lib", "libwget.dylib")
        for path in (tool, lib):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(THIN64)
        key = (lk.OTOOL, "-l", "<tmp>/opt/homebrew/Cellar/wget/9.9/bin/wget",
               "<tmp>/opt/homebrew/Cellar/wget/9.9/lib/libwget.dylib")
        for refs, expected in (([lib, "/gone/libx.dylib"], False), ([lib], True)):
            with self.subTest(refs=refs):
                self.responses[key] = r.FakeResponse(stdout=otool_section(tool, refs) + otool_section(lib, []))
                self.assertIs(health.verify(issue, self.runner(), self.bundle()), expected)

    def test_no_post_check_without_a_reinstall(self):
        self.formula("oldtool", known=False)
        self.formula("gonetool", known=False, receipt=False)
        self.inv.missing = {"oldtool": ["libidn2"]}
        issues = self.detect()
        for code in ("brew-keg-without-receipt", "brew-deleted-formula", "brew-missing-dependency"):
            with self.subTest(code=code):
                issue = self.found(code, issues)[0]
                self.assertNotIn("reinstall", [a.action_id.rsplit(".", 1)[-1] for a in issue.remedies])
                self.assertIsNone(health.verify(issue, self.runner(), self.bundle()))


if __name__ == "__main__":
    unittest.main()

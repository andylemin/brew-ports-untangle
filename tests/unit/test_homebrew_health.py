"""Homebrew health checks: the `brew doctor` parser and a failing and a passing case for every detector"""

import json
import os
import unittest
from unittest import mock

from brew_ports import doctor_report, model, runner as r, state
from brew_ports.homebrew import actions, health, inventory, locate
from brew_ports.model import Blocks, OnFailure, Severity
from brew_ports.report import typed
from tests.unit.helpers import make_instance, make_package
from tests.unit.test_homebrew_health_support import (ARCH, GIT_STATUS, NOW, STAMP, HealthCase, fixture, path_entry,
                                                     service, symlink, write)


class DoctorParserTest(HealthCase):
    """The `brew doctor` parser, and the one probe that names every check"""

    def test_findings_matched_to_checks_by_headline(self):
        report = health.parse_doctor(fixture("doctor-stderr.txt", PREFIX="/opt/homebrew"))
        self.assertEqual(sorted(report.warnings), [
            "check_deleted_formula", "check_deprecated_disabled", "check_for_broken_symlinks",
            "check_for_stray_dylibs", "check_for_stray_headers", "check_for_unlinked_but_not_keg_only"])
        dylibs = report.warnings["check_for_stray_dylibs"]
        self.assertEqual(dylibs[0], "Unbrewed dylibs were found in /usr/local/lib.")
        self.assertEqual(dylibs[-1], "  /usr/local/lib/libstray.dylib")
        self.assertTrue(report.lists("check_deleted_formula", "oldtool"))
        self.assertFalse(report.lists("check_deleted_formula", "wget"))
        self.assertTrue(report.lists("check_for_broken_symlinks", "/opt/homebrew/bin/gone"))
        self.assertEqual(report.errors, ["No check available by the name: check_from_the_future"])

    def test_the_preamble_alone_is_no_finding(self):
        text = fixture("doctor-stderr.txt", PREFIX="/p").split("\nWarning: ")[0]
        self.assertEqual(health.parse_doctor(text).warnings, {})

    def test_one_probe_names_every_check(self):
        fake = self.runner()
        report = health.run_doctor(fake, self.inst)
        self.assertEqual(fake.calls, [ARCH + ("<tmp>/opt/homebrew/bin/brew", "doctor") + actions.DOCTOR_CHECKS])
        self.assertIsNone(report.failure)

    def test_exit_without_readable_findings_fails(self):
        for response, failed in ((r.FakeResponse(exit=1, stderr=fixture("doctor-stderr.txt", PREFIX="/p")), False),
                                 (r.FakeResponse(exit=1, stderr="Error: undefined method\n"), True),
                                 (r.FakeResponse(exit=2), True)):
            with self.subTest(exit=response.exit, stderr=response.stderr[:20]):
                self.doctor = response
                self.assertEqual(health.run_doctor(self.runner(), self.inst).failure is not None, failed)


class PrefixesAndCatalogueTest(HealthCase):
    """Several prefixes, an unusable or dirty instance, and a stale or missing catalogue"""

    def test_several_prefixes(self):
        other = make_instance(prefix=self.path("usr", "local"), repository=self.path("usr", "local", "Homebrew"),
                              drivable=False, usability=model.Usability.MISSING_BINARY, binary=None, version=None)
        self.extra.append((other, None, inventory.HomebrewInventory(instance_prefix=other.prefix)))
        self.formula("wget")
        issue = self.only("brew-several-prefixes")
        self.assertEqual((issue.severity, issue.title), (Severity.INFO, "This Mac has 2 Homebrew installations"))
        self.assertEqual(issue.evidence, [f"Homebrew at {self.prefix}: 1 formula",
                                          f"Homebrew at {other.prefix}: no packages"])
        self.assertEqual(issue.blocks, ())
        self.assertEqual(self.fixes(issue), [
            "Nothing to do. To merge them, `brew-ports plan --target brew --target-prefix` with the folder of the "
            "Homebrew you keep plans a move of every package of the other installations into it."])
        # Where `plan --target brew` has a Homebrew to move into, the note names it.
        with mock.patch("brew_ports.homebrew.locate.choose_target", return_value=self.inst):
            self.assertEqual(self.fixes(self.only("brew-several-prefixes")), [
                "Nothing to do. To merge them, `brew-ports plan --target brew` plans a move of every package of the "
                f"other installations into Homebrew at {self.prefix}; `--target-prefix` names another Homebrew."])

    def test_one_prefix(self):
        self.assertEqual(self.found("brew-several-prefixes", self.detect()), [])

    def test_brew_cannot_run(self):
        self.inst.usability, self.inst.drivable = model.Usability.CANNOT_RUN, False
        self.inst.usability_detail = "Homebrew's portable Ruby failed with exit 86: Bad CPU type in executable"
        issue = self.only("brew-unusable-or-dirty")
        self.assertEqual((issue.severity, issue.title, issue.subject),
                         (Severity.HIGH, f"The `brew` command of Homebrew at {self.prefix} cannot run",
                          self.inst.binary))
        self.assertEqual(issue.blocks, (Blocks.TARGET,))
        self.assertEqual(issue.evidence, ["Homebrew's portable Ruby failed with exit 86: Bad CPU type in executable"])
        self.assertEqual(self.fixes(issue), [
            f"Fix: run it yourself and do what Homebrew asks for: {self.inst.binary} config",
            "A move out of this installation still installs the replacements of its packages, but uninstalls none "
            f"of them one by one. With `--delete {self.prefix}`, `brew-ports plan` plans to delete the installation "
            "whole after the move."])
        self.assertFalse(any("doctor" in call for call in self.fake.calls))

    def test_a_line_to_run_for_an_intel_homebrew_keeps_arch(self):
        """Started without `arch -x86_64` on Apple Silicon, the `brew` of an Intel Homebrew refuses to install"""
        self.inst.arch = "x86_64"
        self.formula("wget", outdated=True)
        issue = self.only("brew-outdated-keg")
        self.assertEqual(self.fixes(issue)[1],
                         f"To upgrade it yourself: arch -x86_64 {self.inst.binary} upgrade --formula wget")
        self.inst.arch = "arm64"
        self.assertEqual(self.fixes(self.only("brew-outdated-keg"))[1],
                         f"To upgrade it yourself: {self.inst.binary} upgrade --formula wget")

    def test_a_homebrew_without_its_brew_command_is_reported(self):
        missing = os.path.join(self.prefix, "bin", "brew")
        self.inst.usability, self.inst.drivable, self.inst.binary = model.Usability.MISSING_BINARY, False, None
        self.inst.usability_detail = f"{missing} is missing"
        issue = self.only("brew-unusable-or-dirty")
        self.assertEqual((issue.title, issue.subject, issue.evidence, issue.blocks),
                         (f"The `brew` command of Homebrew at {self.prefix} cannot run", missing,
                          [f"{missing} is missing"], (Blocks.TARGET,)))
        self.assertEqual(self.fixes(issue)[0],
                         "Fix: install Homebrew there again, or leave it as it is and let a move delete it.")

    def test_dirty_repository(self):
        os.makedirs(os.path.join(self.prefix, ".git"))
        self.run_dir = self.state_dir().new_run()
        self.responses[GIT_STATUS + ("<tmp>/opt/homebrew", "status", "--porcelain")] = r.FakeResponse(
            stdout=" M Library/Homebrew/cmd/doctor.rb\n?? stray.txt\n")
        issue = self.only("brew-unusable-or-dirty")
        self.assertEqual((issue.title, issue.subject, issue.blocks),
                         (f"Homebrew's own files in {self.prefix} were changed", self.prefix, (Blocks.TARGET,)))
        self.assertEqual(issue.evidence, ["`git status` lists 2 changed files: Library/Homebrew/cmd/doctor.rb, "
                                          "stray.txt", "`brew update` can fail over such changes"])
        self.assertTrue(issue.confirm_each)
        self.assertEqual([a.action_id for a in issue.remedies],
                         [f"doctor.brew-unusable-or-dirty.{state.slug(self.prefix)}.{step}"
                          for step in ("offer", "stash", "patch", "recover")])
        self.assertEqual(self.fixes(issue), [
            "Fix: brew-ports doctor --fix (asks, then sets the changes aside with `git stash` and saves a copy of "
            "them in the run folder)",
            "To get the changes back afterwards: " + typed([health.GIT, "-C", self.prefix, "stash", "pop"])])

    def test_clean_repository_and_no_git(self):
        os.makedirs(os.path.join(self.prefix, ".git"))
        self.assertEqual(self.found("brew-unusable-or-dirty", self.detect()), [])
        self.assertIn(GIT_STATUS + ("<tmp>/opt/homebrew", "status", "--porcelain"), self.fake.calls)
        os.rmdir(os.path.join(self.prefix, ".git"))
        self.assertEqual(self.found("brew-unusable-or-dirty", self.detect()), [])
        self.assertFalse(any(call[0] == health.GIT for call in self.fake.calls))

    def test_failed_git_status_is_not_a_pass(self):
        os.makedirs(os.path.join(self.prefix, ".git"))
        self.responses[GIT_STATUS + ("<tmp>/opt/homebrew", "status", "--porcelain")] = r.FakeResponse(
            exit=128, stderr="fatal: detected dubious ownership in repository\n")
        issue = self.only("brew-unusable-or-dirty")
        self.assertEqual((issue.severity, issue.blocks, issue.remedies), (Severity.INFO, (), []))
        self.assertEqual(issue.title, f"Not checked: whether Homebrew's own files in {self.prefix} were changed")
        self.assertEqual(issue.evidence, ["`git status` failed with exit 128: fatal: detected dubious ownership in "
                                          "repository"])

    def test_stale_catalogue(self):
        self.cat_kw["api_mtime"] = NOW - 8 * 86400
        issue = self.only("brew-stale-catalogue")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, self.cat_kw["api_file"]))
        self.assertEqual((issue.title, issue.evidence), ("Homebrew's package list is 8 days old", []))
        self.assertEqual(self.fixes(issue), [
            f"Fix: {self.inst.binary} update",
            "`brew-ports plan --target brew --refresh` runs it too, for the Homebrew that packages move into."])

    def test_missing_catalogue_and_tap_fallback(self):
        self.no_catalogue = True
        issue = self.only("brew-stale-catalogue")
        self.assertEqual(issue.title, "Homebrew's package list is missing")
        self.assertIn("packages.*.jws.json", issue.evidence[0])
        self.assertEqual(issue.evidence[1], "without it, brew-ports cannot tell which installed formulae and casks "
                                            "Homebrew has stopped offering")
        self.no_catalogue = False
        self.cat_kw = {"source": "taps", "frozen": True}
        issue = self.only("brew-stale-catalogue")
        self.assertEqual(issue.title, "Homebrew's package list is read from the homebrew/core tap, which says less "
                                      "about each package")
        self.assertEqual(issue.evidence[1], "HOMEBREW_NO_INSTALL_FROM_API is set, so Homebrew does not download the "
                                            "full list")
        self.assertEqual(self.fixes(issue), ["Nothing to do if you set that variable on purpose."])

    def test_fresh_catalogue(self):
        self.assertEqual(self.found("brew-stale-catalogue", self.detect()), [])


class KegsAndFormulaeTest(HealthCase):
    """Receipt-less, deleted, deprecated and unlinked formulae, broken symlinks and extra kegs"""

    def test_keg_without_receipt(self):
        self.formula("wget", receipt=False)
        issue = self.only("brew-keg-without-receipt")
        self.assertEqual((issue.severity, issue.subject, issue.blocks), (Severity.HIGH, "wget", ()))
        keg = os.path.join(self.prefix, "Cellar", "wget", "1.0")
        self.assertEqual(issue.title, "wget has no install record")
        self.assertEqual(issue.evidence, [
            f"INSTALL_RECEIPT.json, where Homebrew records how it installed a version, is missing from {keg}",
            "without it, brew-ports cannot tell whether you installed it yourself"])
        self.assertEqual([a.argv for a in issue.remedies], [self.brew_argv("reinstall", "--formula", "wget"),
                                                            self.brew_argv("tab", "--installed-on-request", "wget")])
        self.assertEqual((issue.auto_fix, issue.confirm_each, issue.repairs_install), (False, True, True))
        self.assertEqual(self.fixes(issue), [
            f"Fix: brew-ports doctor --fix (asks, then runs `{self.inst.binary} reinstall --formula wget`, then "
            f"`{self.inst.binary} tab --installed-on-request wget`)"])

    def test_kegs_with_receipts(self):
        self.formula("wget")
        self.assertEqual(self.found("brew-keg-without-receipt", self.detect()), [])

    def test_keg_of_a_deleted_formula(self):
        self.formula("oldtool", known=False)
        self.doctor = r.FakeResponse(exit=1, stderr=fixture("doctor-stderr.txt", PREFIX=self.prefix))
        issue = self.only("brew-deleted-formula")
        self.assertEqual((issue.severity, issue.subject), (Severity.MEDIUM, "oldtool"))
        self.assertEqual(issue.title, "oldtool is installed, but Homebrew's package list does not have it under any "
                                      "name")
        self.assertEqual(issue.evidence, ["Homebrew can neither upgrade it nor install it again",
                                          "`brew doctor` reports it too"])
        self.assertEqual([a.argv for a in issue.remedies if a.kind == "command"],
                         [self.brew_argv("uninstall", "--formula", "--force", "oldtool")])
        self.assertEqual(self.fixes(issue)[1:], ["Leave it if you still use it."])
        self.assertTrue(issue.confirm_each)

    def test_known_third_party_renamed_or_no_catalogue(self):
        self.formula("wget")
        self.formula("mytool", known=False, origin="alice/tools")
        self.formula("gitea-runner", rack="act_runner", known=False)
        self.cat_kw["formula_renames"] = {"gitea-runner": "forgejo-runner"}
        self.formulae["forgejo-runner"] = {}
        self.assertEqual(self.found("brew-deleted-formula", self.detect()), [])
        self.no_catalogue = True
        self.assertEqual(self.found("brew-deleted-formula", self.detect()), [])

    def test_deprecated_formula(self):
        self.formula("aamath", deprecated=True)
        self.formulae["aamath"] = {"deprecate_args": {":because": ":unmaintained", ":date": "2026-07-17",
                                                      ":replacement_formula": "newmath"}}
        self.doctor = r.FakeResponse(exit=1, stderr=fixture("doctor-stderr.txt", PREFIX=self.prefix))
        issue = self.only("brew-deprecated-formula")
        self.assertEqual(issue.severity, Severity.INFO)
        self.assertEqual(issue.title, "aamath is deprecated: Homebrew plans to stop offering it")
        self.assertEqual(issue.evidence, ["deprecated on 2026-07-17 (unmaintained); Homebrew suggests newmath instead",
                                          "`brew doctor` reports it too"])
        self.assertEqual(self.fixes(issue), ["Nothing to do for a formula that still works for you."])

    def test_a_disabled_formula_gives_its_dates_and_reason_in_words(self):
        self.formula("oldssl", disabled=True)
        self.formulae["oldssl"] = {"deprecate_args": {":because": ":repo_archived", ":date": "2025-01-10"},
                                   "disable_args": {":because": ":repo_archived", ":date": "2026-01-10"}}
        issue = self.only("brew-deprecated-formula")
        self.assertEqual(issue.title, "oldssl is disabled: Homebrew does not install it any more")
        self.assertEqual(issue.evidence, ["deprecated on 2025-01-10 (repo archived)",
                                          "disabled on 2026-01-10 (repo archived)"])

    def test_current_formula(self):
        self.formula("wget")
        self.assertEqual(self.found("brew-deprecated-formula", self.detect()), [])

    def test_unlinked_formula(self):
        self.formula("unlinked", linked=False)
        issue = self.only("brew-unlinked-keg")
        self.assertEqual(issue.severity, Severity.MEDIUM)
        self.assertEqual(issue.title, f"unlinked is installed, but not linked into {self.prefix}")
        self.assertEqual(issue.evidence, [f"its commands are not in {self.prefix}/bin, and its libraries not in "
                                          f"{self.prefix}/lib"])
        self.assertEqual(issue.remedies[0].argv, self.brew_argv("link", "unlinked"))
        self.assertEqual((issue.remedies[1].argv, issue.remedies[1].manual),
                         ([self.inst.binary, "link", "--overwrite", "--dry-run", "unlinked"], True))
        self.assertEqual((issue.auto_fix, issue.confirm_each, issue.repairs_install), (False, False, True))
        # `doctor --fix` does not offer the link, so the report gives it to the user as a command.
        self.assertEqual(self.fixes(issue), [
            f"Fix: {self.inst.binary} link unlinked",
            f"If `brew link` reports conflicting files, list them: {self.inst.binary} link --overwrite --dry-run "
            "unlinked",
            "A move into this Homebrew links it when a replacement needs it."])

    def test_keg_only_and_linked(self):
        self.formula("openssl@3", linked=False, keg_only=True)
        self.formula("wget")
        self.assertEqual(self.found("brew-unlinked-keg", self.detect()), [])

    def test_broken_symlink(self):
        link = symlink(os.path.join(self.prefix, "bin", "gone"), "../Cellar/gone/1.0/bin/gone")
        issue = self.only("brew-broken-symlink")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, link))
        self.assertEqual((issue.title, issue.evidence), (f"The link {link} points at a file that is gone",
                                                         ["it points at ../Cellar/gone/1.0/bin/gone"]))
        rm = issue.remedies[0]
        self.assertEqual((rm.argv, rm.on_failure, rm.sudo), ([health.RM, link], OnFailure.PROBE, False))
        self.assertTrue(issue.confirm_each)

    def test_working_symlinks(self):
        self.formula("jq")
        write(os.path.join(self.prefix, "Cellar", "jq", "1.0", "bin", "jq"))
        symlink(os.path.join(self.prefix, "bin", "jq"), "../Cellar/jq/1.0/bin/jq")
        self.assertEqual(self.found("brew-broken-symlink", self.detect()), [])

    def test_a_version_that_is_not_in_use(self):
        self.formula("wget", versions=("1.24.5", "1.25.0_2"))
        unused = os.path.join(self.prefix, "Cellar", "wget", "1.24.5")
        issue = self.only("brew-several-versions")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, unused))
        self.assertEqual(issue.remedies[0].argv, [health.RM, "-rf", unused])
        self.assertEqual((issue.title, issue.evidence),
                         ("Version 1.24.5 of wget is installed but not in use",
                          ["in use: 1.25.0_2 (linked and the version other formulae use)"]))
        self.assertTrue(issue.confirm_each)

    def test_the_version_not_in_use_can_be_the_newer_one(self):
        """What is offered for deletion is the version that nothing links, whatever its age"""
        self.formula("wget", versions=("1.25.0_2", "1.24.5"))     # the links go to the last one
        issue = self.only("brew-several-versions")
        self.assertEqual((issue.title, issue.evidence),
                         ("Version 1.25.0_2 of wget is installed but not in use",
                          ["in use: 1.24.5 (linked and the version other formulae use)"]))
        self.assertEqual(issue.remedies[0].description,
                         f"delete the unused version {os.path.join(self.prefix, 'Cellar', 'wget', '1.25.0_2')}")
        self.assertNotIn("old", issue.title)

    def test_one_keg(self):
        self.formula("wget")
        self.assertEqual(self.found("brew-several-versions", self.detect()), [])


class DependenciesAndTapsTest(HealthCase):
    """Missing dependencies, broken linkage, outdated and pinned packages, and taps with local changes"""

    def test_missing_dependencies(self):
        self.formula("wget")
        self.inv.missing = {"wget": ["libidn2", "openssl@3"]}
        issues = self.found("brew-missing-dependency", self.detect())
        self.assertEqual([i.subject for i in issues], ["libidn2", "openssl@3"])
        issue = issues[0]
        self.assertEqual((issue.severity, issue.title, issue.evidence),
                         (Severity.HIGH, "wget needs libidn2, which is not installed", ["`brew missing` reports it"]))
        self.assertEqual(issue.remedies[0].argv,
                         self.brew_argv("install", "--formula", "--as-dependency", "libidn2"))
        self.assertEqual((issue.auto_fix, issue.confirm_each, issue.repairs_install), (True, False, True))
        self.assertEqual(self.fixes(issue), ["Fix: brew-ports doctor --fix (asks, then runs "
                                             f"`{self.inst.binary} install --formula --as-dependency libidn2`)"])

    def test_bare_form_and_nothing_missing(self):
        self.inv.missing = {"": ["libidn2"]}
        self.assertEqual(self.only("brew-missing-dependency").title, "libidn2 is a dependency that is not installed")
        self.inv.missing = {}
        self.assertEqual(self.found("brew-missing-dependency", self.detect()), [])

    def test_broken_linkage(self):
        self.formula("wget")
        binary = os.path.join(self.prefix, "Cellar", "wget", "1.0", "bin", "wget")
        self.linkage = {
            "packages": {f"{self.prefix}|formula|wget": {"binaries": 1, "classes": {"other": 1, "system": 1},
                                                           "broken": [binary]}},
            "binaries": {binary: {"references": [{"name": "/opt/local/lib/libintl.8.dylib", "class": "other"},
                                                 {"name": "/usr/lib/libSystem.B.dylib", "class": "system"}]}}}
        issue = self.only("brew-broken-linkage")
        self.assertEqual(issue.title, "wget loads libraries that are missing or lie outside this Homebrew")
        self.assertEqual(issue.evidence, [f"{binary} loads /opt/local/lib/libintl.8.dylib from another installation"])
        self.assertEqual(issue.remedies[0].argv, self.brew_argv("reinstall", "--formula", "wget"))
        self.assertEqual((issue.severity, issue.confirm_each, issue.repairs_install), (Severity.HIGH, True, True))

    def test_clean_linkage(self):
        self.formula("wget")
        self.linkage = {"packages": {f"{self.prefix}|formula|wget": {"binaries": 1, "classes": {"own": 1},
                                                                       "broken": []}}}
        self.assertEqual(self.found("brew-broken-linkage", self.detect()), [])

    def test_outdated_formula_and_cask(self):
        self.formula("wget", outdated=True)
        self.cask("firefox", outdated=True)
        os.makedirs(os.path.join(self.appdir, "Foo.app"))
        self.inv.outdated_formulae = {"wget": "1.25.0_3"}
        issues = self.found("brew-outdated-keg", self.detect())
        self.assertEqual([(i.subject, i.title) for i in issues],
                         [("wget", "wget has a newer version, 1.25.0_3"), ("firefox", "firefox has a newer version")])
        self.assertEqual(issues[0].evidence, ["installed: 1.0"])
        self.assertEqual((issues[0].remedies[1].argv, issues[0].remedies[1].manual),
                         ([self.inst.binary, "upgrade", "--formula", "wget"], True))
        self.assertEqual(issues[1].remedies[1].argv, [self.inst.binary, "upgrade", "--cask", "firefox"])
        self.assertEqual(self.fixes(issues[0]), [
            "Nothing to do before a move: a move into this Homebrew upgrades what it needs by itself.",
            f"To upgrade it yourself: {self.inst.binary} upgrade --formula wget"])

    def test_current_keg(self):
        self.formula("wget")
        self.assertEqual(self.found("brew-outdated-keg", self.detect()), [])

    def test_pinned_formula(self):
        self.formula("wget", pinned=True, outdated=True)
        issue = self.only("brew-pinned-formula")
        self.assertEqual((issue.severity, issue.title, issue.evidence),
                         (Severity.INFO, "wget is pinned: Homebrew does not upgrade it", ["a newer version exists"]))
        self.assertEqual(self.fixes(issue), ["Nothing to do. A move that needs a newer version of a pinned formula "
                                             "stops until you run `brew unpin` for it."])

    def test_unpinned_formula(self):
        self.formula("wget")
        self.assertEqual(self.found("brew-pinned-formula", self.detect()), [])

    def test_dirty_tap(self):
        tap = self.path("opt", "homebrew", "Library", "Taps", "alice", "homebrew-casks")
        self.inv.taps = [inventory.Tap(name="alice/casks", path=tap, has_git=True, dirty=True,
                                       status=" M Casks/s/sshfs-helper.rb\n")]
        self.run_dir = self.state_dir().new_run()
        issue = self.only("brew-dirty-tap")
        self.assertEqual((issue.severity, issue.subject, issue.confirm_each), (Severity.MEDIUM, "alice/casks", True))
        self.assertEqual((issue.title, issue.evidence[0]),
                         ("The files of the tap alice/casks were changed",
                          "`git status` lists 1 changed file: Casks/s/sshfs-helper.rb"))
        self.assertEqual(issue.remedies[1].argv[-7:], ["-C", tap, "stash", "push", "--include-untracked", "-m",
                                                       "brew-ports " + self.run_dir.run_id])

    def test_clean_tap_and_tap_without_git(self):
        base = self.path("opt", "homebrew", "Library", "Taps")
        self.inv.taps = [inventory.Tap(name="homebrew/core", path=os.path.join(base, "homebrew", "homebrew-core"),
                                       has_git=True, dirty=False),
                         inventory.Tap(name="alice/local", path=os.path.join(base, "alice", "homebrew-local"),
                                       has_git=False, dirty=None)]
        self.assertEqual(self.found("brew-dirty-tap", self.detect()), [])


class PermissionsServicesCasksTest(HealthCase):
    """Unwritable prefixes, orphan services, missing apps, orphan Caskroom directories and stray files"""

    @unittest.skipIf(os.geteuid() == 0, "root writes everywhere")
    def test_directory_not_writable(self):
        locked = os.path.join(self.prefix, "bin")
        os.chmod(locked, 0o555)
        self.addCleanup(os.chmod, locked, 0o755)
        issue = self.only("brew-unwritable-prefix")
        self.assertEqual((issue.severity, issue.subject), (Severity.HIGH, self.prefix))
        self.assertEqual(issue.blocks, (Blocks.TARGET, Blocks.UNINSTALL))
        self.assertEqual((issue.title, issue.evidence),
                         (f"You cannot write to 1 folder of Homebrew at {self.prefix}, so `brew` can neither install "
                          "nor uninstall there", [f"not writable: {locked}"]))
        self.assertEqual(self.fixes(issue), [f'Fix: sudo chown -R "$(whoami)" {locked}'])

    def test_writable_prefix(self):
        self.assertEqual(self.found("brew-unwritable-prefix", self.detect()), [])

    def test_plist_of_a_gone_formula(self):
        plist = os.path.join(self.home, "Library", "LaunchAgents", "homebrew.mxcl.mysql.plist")
        self.services = [service("homebrew.mxcl.mysql", plist, self.prefix, "mysql", loaded=True, domain="gui/501",
                                 pid=321)]
        issue = self.only("brew-orphan-service")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, "homebrew.mxcl.mysql"))
        self.assertEqual((issue.title, issue.evidence),
                         ("The service homebrew.mxcl.mysql is left over from mysql, which is not installed",
                          ["its file is ~/Library/LaunchAgents/homebrew.mxcl.mysql.plist",
                           "it is still loaded, and runs as process 321"]))
        self.assertEqual([(a.argv, a.sudo, a.on_failure) for a in issue.remedies], [
            (["/bin/launchctl", "bootout", "gui/501/homebrew.mxcl.mysql"], False, OnFailure.PROBE),
            ([health.RM, plist], False, OnFailure.PROBE)])
        self.assertTrue(issue.confirm_each)

    def test_installed_formula_and_users_own_job(self):
        self.formula("mysql")
        agents = os.path.join(self.home, "Library", "LaunchAgents")
        self.services = [service("homebrew.mxcl.mysql", os.path.join(agents, "homebrew.mxcl.mysql.plist"),
                                 self.prefix, "mysql"),
                         service("com.alice.backup", os.path.join(agents, "com.alice.backup.plist"), self.prefix,
                                 None, owned=False, package_kind=None)]
        self.assertEqual(self.found("brew-orphan-service", self.detect()), [])

    def test_app_bundle_missing(self):
        self.cask("foo", apps=("Foo.app",))
        issue = self.only("brew-missing-app")
        self.assertEqual((issue.severity, issue.subject), (Severity.MEDIUM, "foo"))
        self.assertEqual(issue.title, f"The app of the cask foo is missing: {os.path.join(self.appdir, 'Foo.app')}")
        self.assertEqual(issue.remedies[0].argv, self.brew_argv("reinstall", "--cask", "foo"))
        self.assertTrue(issue.confirm_each)

    def test_app_bundle_present(self):
        self.cask("foo", apps=("Foo.app",))
        os.makedirs(os.path.join(self.appdir, "Foo.app"))
        self.assertEqual(self.found("brew-missing-app", self.detect()), [])

    def receiptless_cask(self):
        """Add 1password 7.1.2 without a receipt or a caskfile; the catalogue describes 8.11.18 and `1Password.app`

        @returns  the `Casks` directory of its `.metadata`, where the installed caskfile goes
        """
        room = self.cask("1password", version="7.1.2", apps=(), caskfile=False, receipt=False)
        self.casks["1password"] = {"version": "8.11.18", "raw_artifacts": [[":app", "1Password.app"]]}
        return os.path.join(room, ".metadata", "7.1.2", STAMP, "Casks")

    def test_receiptless_cask_judged_by_its_installed_caskfile(self):
        app = os.path.join(self.appdir, "1Password 7.app")
        write(os.path.join(self.receiptless_cask(), "1password.json"),
              json.dumps({"version": "7.1.2", "artifacts": [{"app": ["1Password 7.app"]}]}))
        os.makedirs(app)
        self.assertEqual(self.found("brew-missing-app", self.detect()), [])
        os.rmdir(app)
        self.assertEqual(self.only("brew-missing-app").title, f"The app of the cask 1password is missing: {app}")

    def test_receiptless_cask_judged_by_a_legacy_internal_caskfile(self):
        write(os.path.join(self.receiptless_cask(), "1password.internal.json"),
              json.dumps({"version": "7.1.2", "raw_artifacts": [[":app", "1Password 7.app"]]}))
        self.assertEqual(self.only("brew-missing-app").title, "The app of the cask 1password is missing: "
                         + os.path.join(self.appdir, "1Password 7.app"))

    def test_receiptless_cask_of_another_version_is_not_checked(self):
        write(os.path.join(self.receiptless_cask(), "1password.rb"), 'cask "1password" do\nend\n')
        issue = self.only("brew-missing-app")
        self.assertEqual((issue.severity, issue.title, issue.remedies),
                         (Severity.INFO, "Not checked: whether the app of the cask 1password is in place", []))
        self.assertEqual(issue.evidence, ["Homebrew kept no record of what 1password 7.1.2 installed, and its "
                                          "package list describes version 8.11.18"])
        self.casks["1password"]["version"] = "7.1.2"
        self.assertEqual(self.only("brew-missing-app").title, "The app of the cask 1password is missing: "
                         + os.path.join(self.appdir, "1Password.app"))

    def test_caskroom_directory_without_a_cask(self):
        self.cask("leftover", apps=(), known=False, caskfile=False)
        room = os.path.join(self.prefix, "Caskroom", "leftover")
        # Without a run folder there is nowhere to save the record, so the user gets the command.
        issue = self.only("brew-orphan-caskroom")
        self.assertEqual((issue.confirm_each, self.fixes(issue)[0]), (False, "Fix: " + typed([health.RM, "-rf", room])))
        self.run_dir = self.state_dir().new_run()
        issue = self.only("brew-orphan-caskroom")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, "leftover"))
        self.assertEqual(issue.title, "The cask leftover is installed, but Homebrew's package list does not have it "
                                      "under any name")
        self.assertEqual(issue.evidence, ["neither a tap nor Homebrew's own copy of the cask says what it is, so "
                                          "`brew uninstall` does not work for it", f"its record is the folder {room}"])
        _, archive, remove, note = issue.remedies
        self.assertEqual(archive.argv, [health.TAR, "-czf", "-", "-C", os.path.dirname(room), "leftover"])
        self.assertEqual(archive.dst, os.path.join(self.run_dir.path, "backup", "caskroom",
                                                   room.replace("/", "%") + ".tar.gz"))
        self.assertEqual(remove.argv, [health.RM, "-rf", room])
        self.assertFalse(archive.sudo or remove.sudo)
        self.assertEqual(note.kind, "note")
        self.assertTrue(issue.confirm_each)
        self.assertEqual(self.fixes(issue), [
            "Fix: brew-ports doctor --fix (asks, then saves Homebrew's record of the cask in the run folder, then "
            "deletes it)",
            "The apps and files that the cask installed stay: move them to the Trash yourself if you do not want "
            "them."])

    def test_cask_defined_by_tap_caskfile_or_catalogue(self):
        self.cask("sshfs-helper", apps=(), known=False, caskfile=False)
        write(os.path.join(self.prefix, "Library", "Taps", "alice", "homebrew-casks", "Casks", "s", "sshfs-helper.rb"))
        self.cask("local-app", apps=(), known=False, caskfile=True)
        self.cask("firefox", apps=(), known=True, caskfile=False)
        self.cat_kw["cask_renames"] = {"oldbox": "newbox"}
        self.cask("oldbox", apps=(), known=False, caskfile=False)
        self.casks["newbox"] = {}
        self.assertEqual(self.found("brew-orphan-caskroom", self.detect()), [])
        self.no_catalogue = True
        self.cask("unknowable", apps=(), known=False, caskfile=False)
        self.assertEqual(self.found("brew-orphan-caskroom", self.detect()), [])

    def test_stray_files_reported_once_for_the_host(self):
        self.doctor = r.FakeResponse(exit=1, stderr=fixture("doctor-stderr.txt", PREFIX=self.prefix))
        other = make_instance(prefix=self.path("usr", "local"), repository=self.path("usr", "local", "Homebrew"))
        self.extra.append((other, None, inventory.HomebrewInventory(instance_prefix=other.prefix, used_json=True)))
        issues = self.found("brew-strays-in-usr-local", self.detect())
        self.assertEqual([(i.subject, i.title) for i in issues], [
            ("/usr/local/lib", "/usr/local/lib holds libraries that Homebrew did not install"),
            ("/usr/local/include", "/usr/local/include holds header files that Homebrew did not install")])
        self.assertEqual([i.evidence[0] for i in issues], ["libstray.dylib", "openssl/*"])
        self.assertEqual(issues[0].evidence[1], "software that Homebrew or MacPorts builds can pick them up by mistake")
        # The files are this Mac's, not one Homebrew's: the finding names no installation.
        self.assertEqual((issues[0].severity, issues[0].instance_prefix), (Severity.MEDIUM, None))
        self.assertEqual(self.fixes(issues[0]), ["Fix: delete or move them, unless you put them there on purpose."])
        self.assertEqual(sum(1 for call in self.fake.calls if "doctor" in call), 2)

    def test_strays_on_an_intel_host_or_clean_doctor(self):
        self.assertEqual(self.found("brew-strays-in-usr-local", self.detect()), [])
        self.host_arch = "x86_64"
        self.inst.arch = "x86_64"
        self.doctor = r.FakeResponse(exit=1, stderr=fixture("doctor-stderr.txt", PREFIX=self.prefix))
        self.assertEqual(self.found("brew-strays-in-usr-local", self.detect()), [])


class EnvironmentAndOwnershipTest(HealthCase):
    """PATH order, renamed racks, a degraded inventory, root-owned kegs and `brew.env` overrides"""

    def test_usr_bin_first_on_path(self):
        self.environment = {"live": {"PATH": [path_entry("/usr/bin"), path_entry(os.path.join(self.prefix, "bin"))]},
                            "records": []}
        issue = self.only("brew-path-order")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, os.path.join(self.prefix, "bin")))
        self.assertEqual(issue.title, f"/usr/bin comes before {self.prefix}/bin on your PATH, so a command of macOS "
                                      "wins over Homebrew's command of the same name")
        self.assertEqual(issue.evidence, [f"/usr/bin is entry 1 of your PATH, and {self.prefix}/bin is entry 2"])
        # The fix by hand holds for every Homebrew; `doctor` names env-cleanup for the one that command keeps.
        self.assertEqual(self.fixes(issue), [
            f"Fix, if this is the Homebrew you keep: put {self.prefix}/bin in front of /usr/bin in your shell's "
            "login file."])

    def test_prefix_first_on_path(self):
        self.environment = {"live": {"PATH": [path_entry(os.path.join(self.prefix, "bin")), path_entry("/usr/bin")]}}
        self.assertEqual(self.found("brew-path-order", self.detect()), [])

    def test_rack_under_its_old_name(self):
        self.formula("gitea-runner", rack="act_runner")
        self.cat_kw["formula_renames"] = {"act_runner": "gitea-runner"}
        issue = self.only("brew-renamed-keg")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, "act_runner"))
        self.assertEqual((issue.title, issue.evidence),
                         ("Homebrew renamed act_runner to gitea-runner, and the installed copy still has the old name",
                          [f"its folder is {os.path.join(self.prefix, 'Cellar', 'act_runner')}"]))
        self.assertEqual(issue.remedies[0].argv, self.brew_argv("migrate", "act_runner"))
        self.assertEqual((issue.auto_fix, issue.confirm_each, issue.repairs_install), (True, False, True))

    def test_rack_under_its_current_name(self):
        self.formula("gitea-runner")
        self.cat_kw["formula_renames"] = {"act_runner": "gitea-runner"}
        self.assertEqual(self.found("brew-renamed-keg", self.detect()), [])

    def test_degraded_inventory(self):
        self.inst.inventory_error = "brew info --json=v2 --installed timed out"
        self.inv.used_json = False
        issue = self.only("brew-degraded-inventory")
        self.assertEqual((issue.severity, issue.subject), (Severity.HIGH, self.prefix))
        self.assertEqual(issue.blocks, (Blocks.TARGET, Blocks.CASKS, Blocks.REMOVE))
        self.assertEqual((issue.title, issue.evidence),
                         ("`brew info` failed, so brew-ports knows only part of what this Homebrew has installed",
                          ["brew info --json=v2 --installed timed out"]))
        self.assertEqual(self.fixes(issue), [
            f"Fix: run it yourself and resolve what Homebrew reports: {self.inst.binary} info --json=v2 --installed",
            "Then run `brew-ports doctor --rescan`."])

    def test_homebrews_own_error_line_leads_the_evidence(self):
        self.inst.inventory_error = ("brew info --json=v2 --installed failed with exit 1: Warning: a first line\n"
                                     "a line of detail\n"
                                     "Error: the line that names the cause")
        self.inv.used_json = False
        self.assertEqual(self.only("brew-degraded-inventory").evidence, [
            "brew info --json=v2 --installed failed with exit 1: Warning: a first line",
            "Error: the line that names the cause",
            "a line of detail"])

    def test_no_degraded_inventory_for_macports(self):
        ports = make_instance(model.Manager.PORTS, prefix=self.path("opt", "local"), drivable=False,
                              usability=model.Usability.DAMAGED_REGISTRY, inventory_error="database disk image is "
                              "malformed", inventory_known=False)
        bundle = self.bundle()
        bundle.result.instances.append(ports)
        bundle.ports.append((ports, None, None))
        issues = self.detect(bundle)
        self.assertEqual(self.found("brew-degraded-inventory", issues), [])
        self.assertNotIn(ports.prefix, {i.instance_prefix for i in issues})

    def test_root_owned_keg_paths(self):
        self.formula("postgresql@16", keg_only=True, linked=False)
        keg = os.path.join(self.prefix, "Cellar", "postgresql@16", "1.0")
        self.inv.root_owned = {"postgresql@16": [os.path.join(self.prefix, "opt", "postgresql@16"), keg]}
        issue = self.only("brew-root-owned-keg")
        self.assertEqual((issue.severity, issue.subject, issue.blocks), (Severity.HIGH, "postgresql@16",
                                                                         (Blocks.TARGET,)))
        self.assertEqual((issue.title, issue.evidence),
                         ("Files of postgresql@16 belong to root, so `brew` cannot change them",
                          [f"{os.path.join(self.prefix, 'opt', 'postgresql@16')}, {keg}",
                           "a move out of this Homebrew leaves postgresql@16 installed while they do"]))
        self.assertTrue(all(a.manual for a in issue.remedies))
        rack, opt = os.path.dirname(keg), os.path.join(self.prefix, "opt", "postgresql@16")
        self.assertEqual(self.fixes(issue), [
            f"Fix: sudo {self.inst.binary} services stop postgresql@16",
            f"Then give the files back to yourself: sudo chown -R -h \"$(whoami)\" {rack} {opt}"])
        self.assertEqual((issue.auto_fix, issue.confirm_each, issue.repairs_install), (False, False, False))

    def test_a_long_list_of_root_owned_files_is_kept_whole(self):
        self.formula("redis")
        keg = os.path.join(self.prefix, "Cellar", "redis", "1.0")
        self.inv.root_owned = {"redis": [os.path.join(keg, f"file{n}") for n in range(12)]}
        issue = self.only("brew-root-owned-keg")
        # The first line names eight; the lines after the second name each file, for --verbose and doctor.json.
        self.assertTrue(issue.evidence[0].endswith("and 4 more"))
        self.assertEqual(issue.evidence[2:], self.inv.root_owned["redis"])

    def test_user_owned_kegs(self):
        self.formula("postgresql@16")
        self.assertEqual(self.found("brew-root-owned-keg", self.detect()), [])

    def test_brew_env_lines_that_change_the_profile(self):
        system_file, user_file = "/etc/homebrew/brew.env", os.path.join(self.home, ".homebrew", "brew.env")
        self.inv.brew_env = [locate.EnvLine(system_file, 2, "HOMEBREW_NO_AUTOREMOVE", ""),
                             locate.EnvLine(system_file, 3, "HOMEBREW_NO_SUDO", "1"),
                             locate.EnvLine(user_file, 1, "HOMEBREW_DEVELOPER", "1"),
                             locate.EnvLine(user_file, 2, "HOMEBREW_NO_INSTALL_UPGRADE", "false")]
        issues = self.found("brew-env-override", self.detect())
        self.assertEqual([(i.subject, i.severity, i.blocks) for i in issues],
                         [(system_file, Severity.HIGH, (Blocks.ANY,)), (user_file, Severity.HIGH, (Blocks.ANY,))])
        self.assertEqual(issues[0].title, f"{system_file} changes settings that brew-ports relies on when it runs "
                                          "`brew`")
        self.assertEqual(issues[0].evidence, ["line 2: HOMEBREW_NO_AUTOREMOVE= turns off HOMEBREW_NO_AUTOREMOVE=1, "
                                              "which brew-ports sets for every `brew` command it runs"])
        self.assertEqual(issues[1].evidence[0], "line 1: HOMEBREW_DEVELOPER=1 sets HOMEBREW_DEVELOPER, which "
                                                "brew-ports keeps away from every `brew` command it runs")
        self.assertEqual([e.split(":")[0] for e in issues[1].evidence], ["line 1", "line 2"])
        self.assertEqual(self.fixes(issues[1]), ["Fix: remove these lines from ~/.homebrew/brew.env, or put a # in "
                                                 "front of each."])

    def test_brew_env_lines_that_keep_the_profile(self):
        system_file = "/etc/homebrew/brew.env"
        self.inv.brew_env = [locate.EnvLine(system_file, 1, "HOMEBREW_NO_SUDO", "1"),
                             locate.EnvLine(system_file, 2, "HOMEBREW_NO_AUTO_UPDATE", "yes"),
                             locate.EnvLine(system_file, 3, "HOMEBREW_NO_AUTOREMOVE", ""),
                             locate.EnvLine(system_file, 4, "HOMEBREW_DEBUG", ""),
                             locate.EnvLine(system_file, 5, "HOMEBREW_NO_ANALYTICS", "1"),
                             locate.EnvLine("/Users/alice/.homebrew/brew.env", 1, "HOMEBREW_NO_AUTOREMOVE", "1")]
        self.assertEqual(self.found("brew-env-override", self.detect()), [])
        self.inv.brew_env = [locate.EnvLine(system_file, 1, "HOMEBREW_NO_SUDO", "")]
        self.inst.usability, self.inst.drivable = model.Usability.CANNOT_RUN, False
        self.assertEqual(self.found("brew-env-override", self.detect()), [])


class NotCheckedTest(HealthCase):
    """The not-checked findings of the checks that an undrivable instance or a failed probe skips"""

    @staticmethod
    def unchecked(issues):
        """Return the findings that stand for a check that could not run

        @param issues  the findings
        @returns       those the report lists under its last heading
        """
        return [i for i in issues if doctor_report.unchecked(i)]

    def test_undrivable_instance_skips_brew_checks(self):
        self.inst.usability, self.inst.drivable = model.Usability.MISSING_BINARY, False
        self.inst.usability_detail = f"{self.prefix}/bin/brew is missing"
        self.inv.used_json = False
        skipped = self.unchecked(self.detect())
        self.assertEqual([(i.code, i.title) for i in skipped], [
            ("brew-missing-dependency", "Not checked: whether an installed formula lacks a dependency"),
            ("brew-outdated-keg", "Not checked: which packages have a newer version"),
            ("brew-strays-in-usr-local", "Not checked: whether /usr/local holds libraries or header files that "
                                         "Homebrew did not install")])
        self.assertTrue(all(i.severity is Severity.INFO and i.blocks == () and not i.remedies for i in skipped))
        self.assertEqual(skipped[0].evidence, [f"its `brew` command cannot run: {self.prefix}/bin/brew is missing"])
        self.assertEqual(skipped[2].evidence, ["no Homebrew on this Mac can run `brew doctor`, which finds them"])
        self.assertEqual(self.fake.calls, [])

    def test_a_failed_brew_info_skips_the_probes_it_gates(self):
        self.inst.inventory_error = "brew info --json=v2 --installed failed with exit 1: Error: no internet"
        self.inv.used_json = False
        issues = self.detect()
        self.assertEqual([(i.code, i.evidence) for i in self.unchecked(issues)], [
            ("brew-missing-dependency", ["`brew info` failed there, so `brew missing` was not run"]),
            ("brew-outdated-keg", ["`brew info` failed there, so `brew outdated` was not run"])])
        self.assertEqual(len(self.found("brew-degraded-inventory", issues)), 1)

    def test_a_failed_brew_missing_skips_one_check(self):
        self.inst.inventory_error = self.inv.inventory_error = "brew missing timed out"
        issues = self.detect()
        self.assertEqual([(i.code, i.evidence) for i in self.unchecked(issues)],
                         [("brew-missing-dependency", ["brew missing timed out"])])
        self.assertEqual(self.found("brew-degraded-inventory", issues) + self.found("brew-failed-probe", issues), [])

    def test_a_failed_outdated_or_deps_probe_keeps_the_inventory(self):
        outdated = "brew outdated --json=v2 failed with exit 1: Error: no internet"
        deps = "brew deps --formula --installed --for-each timed out"
        self.inst.inventory_error = self.inv.inventory_error = f"{outdated}; {deps}"
        issues = self.detect()
        self.assertEqual(self.found("brew-degraded-inventory", issues), [])
        probe = self.only("brew-failed-probe")
        self.assertEqual((probe.severity, probe.blocks), (Severity.INFO, ()))
        self.assertEqual(probe.title, "`brew outdated` and `brew deps` failed, so brew-ports knows less about this "
                                      "Homebrew")
        self.assertEqual(probe.evidence, ["packages with a newer version are listed without the number of that version",
                                          "dependencies come from Homebrew's install records alone",
                                          f"{outdated}; {deps}"])
        self.assertEqual(self.fixes(probe), ["Nothing to do: brew-ports works with what `brew info` gave it."])


class OrderTest(HealthCase):
    """The table order of the findings, and the distinct action ids of two prefixes"""

    def test_findings_come_in_table_order(self):
        self.formula("wget", receipt=False, linked=False, pinned=True)
        self.inv.missing = {"wget": ["libidn2"]}
        codes = [i.code for i in self.detect()]
        self.assertEqual(codes, sorted(codes, key=list(health.SEVERITY).index))
        self.assertEqual(codes, ["brew-keg-without-receipt", "brew-unlinked-keg", "brew-missing-dependency",
                                 "brew-pinned-formula"])

    def test_two_prefixes_get_distinct_action_ids(self):
        self.formula("wget", receipt=False)
        other_prefix = self.path("usr", "local")
        os.makedirs(os.path.join(other_prefix, "Homebrew", "Library", "Homebrew"))
        other = make_instance(prefix=other_prefix, repository=os.path.join(other_prefix, "Homebrew"), arch="x86_64")
        keg = os.path.join(other_prefix, "Cellar", "wget", "1.0")
        os.makedirs(keg)
        inv = inventory.HomebrewInventory(instance_prefix=other_prefix, used_json=True, kegs={"wget": [keg]},
                                          receiptless_kegs=[keg],
                                          packages=[make_package("wget", prefix=other_prefix, receipt_ok=False,
                                                                 requested=None)])
        self.extra.append((other, None, inv))
        ids = [a.action_id for i in self.found("brew-keg-without-receipt", self.detect()) for a in i.remedies]
        self.assertEqual(len(ids), 4)
        self.assertEqual(len(set(ids)), 4)
        self.assertIn(("/usr/bin/arch", "-x86_64", "<tmp>/usr/local/bin/brew", "reinstall", "--formula", "wget"),
                      [tuple(self.fake.key(a.argv)) for i in self.issues for a in i.remedies])


if __name__ == "__main__":
    unittest.main()

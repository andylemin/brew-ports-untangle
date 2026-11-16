"""Homebrew health checks: the `brew doctor` parser and a failing and a passing case for every detector"""

import json
import os
import unittest

from brew_ports import model, runner as r, state
from brew_ports.homebrew import actions, health, inventory, locate
from brew_ports.model import Blocks, OnFailure, Severity
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
        issue = self.only("brew-several-prefixes")
        self.assertEqual(issue.severity, Severity.INFO)
        self.assertEqual(issue.evidence[:2], [f"{self.prefix}: usable, Homebrew 7.0.11",
                                              f"{other.prefix}: missing-binary"])
        self.assertEqual((issue.remedies, issue.blocks), ([], ()))

    def test_one_prefix(self):
        self.assertEqual(self.found("brew-several-prefixes", self.detect()), [])

    def test_brew_cannot_run(self):
        self.inst.usability, self.inst.drivable = model.Usability.CANNOT_RUN, False
        self.inst.usability_detail = "Homebrew's portable Ruby failed with exit 86: Bad CPU type in executable"
        issue = self.only("brew-unusable-or-dirty")
        self.assertEqual((issue.severity, issue.title, issue.subject), (Severity.HIGH, "brew cannot run",
                                                                       self.inst.binary))
        self.assertEqual((issue.remedies, issue.blocks), ([], (Blocks.TARGET,)))
        self.assertIn("Bad CPU type", issue.evidence[0])
        self.assertFalse(any("doctor" in call for call in self.fake.calls))

    def test_dirty_repository(self):
        os.makedirs(os.path.join(self.prefix, ".git"))
        self.run_dir = self.state_dir().new_run()
        self.responses[GIT_STATUS + ("<tmp>/opt/homebrew", "status", "--porcelain")] = r.FakeResponse(
            stdout=" M Library/Homebrew/cmd/doctor.rb\n?? stray.txt\n")
        issue = self.only("brew-unusable-or-dirty")
        self.assertEqual((issue.title, issue.subject, issue.blocks),
                         ("Homebrew repository has local changes", self.prefix, (Blocks.TARGET,)))
        self.assertEqual(issue.evidence[1:], ["   M Library/Homebrew/cmd/doctor.rb", "  ?? stray.txt"])
        self.assertTrue(issue.confirm_each)
        self.assertEqual([a.action_id for a in issue.remedies],
                         [f"doctor.brew-unusable-or-dirty.{state.slug(self.prefix)}.{step}"
                          for step in ("stash", "patch", "recover")])

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
        self.assertIn("dubious ownership", issue.evidence[0])

    def test_stale_catalogue(self):
        self.cat_kw["api_mtime"] = NOW - 8 * 86400
        issue = self.only("brew-stale-catalogue")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, self.cat_kw["api_file"]))
        self.assertEqual(issue.evidence, [f"{self.cat_kw['api_file']} is 8 days old"])
        self.assertEqual([(a.kind, a.manual) for a in issue.remedies], [("note", True)])
        self.assertIn("plan --refresh", issue.remedies[0].description)

    def test_missing_catalogue_and_tap_fallback(self):
        self.no_catalogue = True
        issue = self.only("brew-stale-catalogue")
        self.assertIn("packages.*.jws.json", issue.evidence[0])
        self.assertIn("deleted formulae and orphan Caskroom directories are not checked without a catalogue",
                      issue.evidence)
        self.no_catalogue = False
        self.cat_kw = {"source": "taps", "frozen": True}
        self.assertIn("HOMEBREW_NO_INSTALL_FROM_API", self.only("brew-stale-catalogue").evidence[0])

    def test_fresh_catalogue(self):
        self.assertEqual(self.found("brew-stale-catalogue", self.detect()), [])


class KegsAndFormulaeTest(HealthCase):
    """Receipt-less, deleted, deprecated and unlinked formulae, broken symlinks and extra kegs"""

    def test_keg_without_receipt(self):
        self.formula("wget", receipt=False)
        issue = self.only("brew-keg-without-receipt")
        self.assertEqual((issue.severity, issue.subject, issue.blocks), (Severity.HIGH, "wget", ()))
        keg = os.path.join(self.prefix, "Cellar", "wget", "1.0")
        self.assertEqual(issue.evidence, [f"no INSTALL_RECEIPT.json in {keg}"])
        self.assertEqual([a.argv for a in issue.remedies], [self.brew_argv("reinstall", "--formula", "wget"),
                                                            self.brew_argv("tab", "--installed-on-request", "wget")])
        self.assertEqual((issue.auto_fix, issue.confirm_each, issue.repairs_install), (False, True, True))

    def test_kegs_with_receipts(self):
        self.formula("wget")
        self.assertEqual(self.found("brew-keg-without-receipt", self.detect()), [])

    def test_keg_of_a_deleted_formula(self):
        self.formula("oldtool", known=False)
        self.doctor = r.FakeResponse(exit=1, stderr=fixture("doctor-stderr.txt", PREFIX=self.prefix))
        issue = self.only("brew-deleted-formula")
        self.assertEqual((issue.severity, issue.subject), (Severity.MEDIUM, "oldtool"))
        self.assertIn("brew doctor: Some installed kegs have no formulae!", issue.evidence)
        self.assertEqual([a.argv for a in issue.remedies],
                         [self.brew_argv("uninstall", "--formula", "--force", "oldtool")])
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
        self.assertEqual(issue.evidence, ["aamath is deprecated",
                                          "deprecation date 2026-07-17 (unmaintained); replacement: newmath",
                                          "brew doctor: Some installed formulae are deprecated or disabled."])
        self.assertEqual(issue.remedies, [])

    def test_current_formula(self):
        self.formula("wget")
        self.assertEqual(self.found("brew-deprecated-formula", self.detect()), [])

    def test_unlinked_formula(self):
        self.formula("unlinked", linked=False)
        issue = self.only("brew-unlinked-keg")
        self.assertEqual(issue.severity, Severity.MEDIUM)
        self.assertEqual(issue.remedies[0].argv, self.brew_argv("link", "unlinked"))
        self.assertEqual((issue.remedies[1].argv, issue.remedies[1].manual),
                         ([self.inst.binary, "link", "--overwrite", "--dry-run", "unlinked"], True))
        self.assertEqual((issue.auto_fix, issue.confirm_each, issue.repairs_install), (False, False, True))

    def test_keg_only_and_linked(self):
        self.formula("openssl@3", linked=False, keg_only=True)
        self.formula("wget")
        self.assertEqual(self.found("brew-unlinked-keg", self.detect()), [])

    def test_broken_symlink(self):
        link = symlink(os.path.join(self.prefix, "bin", "gone"), "../Cellar/gone/1.0/bin/gone")
        issue = self.only("brew-broken-symlink")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, link))
        self.assertEqual(issue.evidence, [f"{link} -> ../Cellar/gone/1.0/bin/gone, which does not exist"])
        rm = issue.remedies[0]
        self.assertEqual((rm.argv, rm.on_failure, rm.sudo), ([health.RM, link], OnFailure.PROBE, False))
        self.assertTrue(issue.confirm_each)

    def test_working_symlinks(self):
        self.formula("jq")
        write(os.path.join(self.prefix, "Cellar", "jq", "1.0", "bin", "jq"))
        symlink(os.path.join(self.prefix, "bin", "jq"), "../Cellar/jq/1.0/bin/jq")
        self.assertEqual(self.found("brew-broken-symlink", self.detect()), [])

    def test_old_keg(self):
        self.formula("wget", versions=("1.24.5", "1.25.0_2"))
        old = os.path.join(self.prefix, "Cellar", "wget", "1.24.5")
        issue = self.only("brew-several-versions")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, old))
        self.assertEqual(issue.remedies[0].argv, [health.RM, "-rf", old])
        self.assertIn(f"keeps {os.path.join(self.prefix, 'Cellar', 'wget', '1.25.0_2')} (linked and opt link)",
                      issue.evidence)
        self.assertTrue(issue.confirm_each)

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
        self.assertEqual((issue.severity, issue.evidence), (Severity.HIGH, ["brew missing: wget: libidn2 openssl@3"]))
        self.assertEqual(issue.remedies[0].argv,
                         self.brew_argv("install", "--formula", "--as-dependency", "libidn2"))
        self.assertEqual((issue.auto_fix, issue.confirm_each, issue.repairs_install), (True, False, True))

    def test_bare_form_and_nothing_missing(self):
        self.inv.missing = {"": ["libidn2"]}
        self.assertEqual(self.only("brew-missing-dependency").evidence, ["brew missing: libidn2"])
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
        self.assertEqual(issue.evidence, [f"{binary}: other reference /opt/local/lib/libintl.8.dylib"])
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
                         [("wget", "Outdated keg"), ("firefox", "Outdated cask")])
        self.assertEqual(issues[0].evidence, ["installed 1.0, current 1.25.0_3"])
        self.assertEqual((issues[0].remedies[0].argv, issues[0].remedies[0].manual),
                         ([self.inst.binary, "upgrade", "--formula", "wget"], True))
        self.assertEqual(issues[1].remedies[0].argv, [self.inst.binary, "upgrade", "--cask", "firefox"])

    def test_current_keg(self):
        self.formula("wget")
        self.assertEqual(self.found("brew-outdated-keg", self.detect()), [])

    def test_pinned_formula(self):
        self.formula("wget", pinned=True, outdated=True)
        issue = self.only("brew-pinned-formula")
        self.assertEqual((issue.severity, issue.evidence[0]), (Severity.INFO, "wget is pinned and outdated"))

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
        self.assertEqual(issue.remedies[0].argv[-7:], ["-C", tap, "stash", "push", "--include-untracked", "-m",
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
        self.assertEqual(issue.evidence, [f"{locked} is not writable"])
        self.assertTrue(issue.remedies[0].manual)
        self.assertIn("chown", issue.remedies[0].description)

    def test_writable_prefix(self):
        self.assertEqual(self.found("brew-unwritable-prefix", self.detect()), [])

    def test_plist_of_a_gone_formula(self):
        plist = os.path.join(self.home, "Library", "LaunchAgents", "homebrew.mxcl.mysql.plist")
        self.services = [service("homebrew.mxcl.mysql", plist, self.prefix, "mysql", loaded=True, domain="gui/501",
                                 pid=321)]
        issue = self.only("brew-orphan-service")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, "homebrew.mxcl.mysql"))
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
        self.assertEqual(issue.evidence, [f"{os.path.join(self.appdir, 'Foo.app')} is missing"])
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
        self.assertEqual(self.only("brew-missing-app").evidence, [f"{app} is missing"])

    def test_receiptless_cask_judged_by_a_legacy_internal_caskfile(self):
        write(os.path.join(self.receiptless_cask(), "1password.internal.json"),
              json.dumps({"version": "7.1.2", "raw_artifacts": [[":app", "1Password 7.app"]]}))
        self.assertEqual(self.only("brew-missing-app").evidence,
                         [f"{os.path.join(self.appdir, '1Password 7.app')} is missing"])

    def test_receiptless_cask_of_another_version_is_not_evaluated(self):
        write(os.path.join(self.receiptless_cask(), "1password.rb"), 'cask "1password" do\nend\n')
        issue = self.only("brew-missing-app")
        self.assertEqual((issue.severity, issue.title, issue.remedies),
                         (Severity.INFO, "Cask app bundle missing: not evaluated", []))
        self.assertIn("1password 7.1.2", issue.evidence[0])
        self.assertIn("8.11.18", issue.evidence[0])
        self.casks["1password"]["version"] = "7.1.2"
        self.assertEqual(self.only("brew-missing-app").evidence,
                         [f"{os.path.join(self.appdir, '1Password.app')} is missing"])

    def test_caskroom_directory_without_a_cask(self):
        self.cask("leftover", apps=(), known=False, caskfile=False)
        issue = self.only("brew-orphan-caskroom")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, "leftover"))
        room = os.path.join(self.prefix, "Caskroom", "leftover")
        archive, remove, note = issue.remedies
        self.assertEqual(archive.argv, [health.TAR, "-czf", "-", "-C", os.path.dirname(room), "leftover"])
        self.assertTrue(archive.dst.endswith(os.path.join("backup", "caskroom", room.replace("/", "%") + ".tar.gz")))
        self.assertEqual(remove.argv, [health.RM, "-rf", room])
        self.assertFalse(archive.sudo or remove.sudo)
        self.assertEqual(note.kind, "note")
        self.assertTrue(issue.confirm_each)

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
        self.assertEqual([(i.subject, i.title) for i in issues],
                         [("/usr/local/lib", "Stray dylibs in /usr/local/lib"),
                          ("/usr/local/include", "Stray headers in /usr/local/include")])
        self.assertEqual(issues[0].evidence[:2], ["brew doctor check_for_stray_dylibs:",
                                                  "Unbrewed dylibs were found in /usr/local/lib."])
        self.assertEqual((issues[0].severity, issues[0].remedies[0].manual), (Severity.MEDIUM, True))
        self.assertIn("/usr/local/lib/libstray.dylib", issues[0].remedies[0].description)
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
        self.assertEqual(issue.evidence, [f"live PATH entry 1 is /usr/bin, entry 2 is {self.prefix}/bin"])
        self.assertIn("adds the PATH line", issue.remedies[0].description)
        self.environment["records"] = [{"kind": "shellenv", "file": "~/.zprofile", "lineno": 3}]
        self.assertIn("fixes the PATH order", self.only("brew-path-order").remedies[0].description)

    def test_prefix_first_on_path(self):
        self.environment = {"live": {"PATH": [path_entry(os.path.join(self.prefix, "bin")), path_entry("/usr/bin")]}}
        self.assertEqual(self.found("brew-path-order", self.detect()), [])

    def test_rack_under_its_old_name(self):
        self.formula("gitea-runner", rack="act_runner")
        self.cat_kw["formula_renames"] = {"act_runner": "gitea-runner"}
        issue = self.only("brew-renamed-keg")
        self.assertEqual((issue.severity, issue.subject), (Severity.LOW, "act_runner"))
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
        self.assertEqual(issue.evidence[0], "brew info --json=v2 --installed timed out")

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
        self.assertEqual(issue.evidence[1], f"owned by root: {keg}")
        self.assertTrue(all(a.manual for a in issue.remedies))
        self.assertEqual(issue.remedies[0].description, f"sudo {self.inst.binary} services stop postgresql@16")
        self.assertEqual((issue.auto_fix, issue.confirm_each, issue.repairs_install), (False, False, False))

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
        self.assertEqual(len(issues[0].evidence), 1)
        self.assertTrue(issues[0].evidence[0].startswith(f"{system_file}:2: HOMEBREW_NO_AUTOREMOVE= turns off"))
        self.assertEqual([e.split(":")[1] for e in issues[1].evidence], ["1", "2"])
        self.assertTrue(issues[0].remedies[0].manual)

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


class NotEvaluatedTest(HealthCase):
    """The not-evaluated findings of the checks that an undrivable instance or a failed probe skips"""

    def test_undrivable_instance_skips_brew_checks(self):
        self.inst.usability, self.inst.drivable = model.Usability.MISSING_BINARY, False
        self.inst.usability_detail = f"{self.prefix}/bin/brew is missing"
        self.inv.used_json = False
        issues = self.detect()
        skipped = [i for i in issues if i.title.endswith(": not evaluated")]
        self.assertEqual([i.code for i in skipped],
                         ["brew-missing-dependency", "brew-outdated-keg", "brew-strays-in-usr-local"])
        self.assertTrue(all(i.severity is Severity.INFO and i.blocks == () and not i.remedies for i in skipped))
        self.assertIn(f"brew cannot run on {self.prefix} (missing-binary", skipped[0].evidence[0])
        self.assertEqual(self.fake.calls, [])

    def test_a_failed_brew_info_skips_the_probes_it_gates(self):
        self.inst.inventory_error = "brew info --json=v2 --installed failed with exit 1: Error: no internet"
        self.inv.used_json = False
        issues = self.detect()
        self.assertEqual([i.code for i in issues if i.title.endswith(": not evaluated")],
                         ["brew-missing-dependency", "brew-outdated-keg"])
        self.assertEqual(len(self.found("brew-degraded-inventory", issues)), 1)

    def test_a_failed_brew_missing_skips_one_check(self):
        self.inst.inventory_error = self.inv.inventory_error = "brew missing timed out"
        issues = self.detect()
        self.assertEqual([i.code for i in issues if i.title.endswith(": not evaluated")], ["brew-missing-dependency"])
        self.assertIn("brew missing timed out", self.found("brew-missing-dependency", issues)[0].evidence[0])
        self.assertEqual(self.found("brew-degraded-inventory", issues) + self.found("brew-failed-probe", issues), [])

    def test_a_failed_outdated_or_deps_probe_keeps_the_inventory(self):
        outdated = "brew outdated --json=v2 failed with exit 1: Error: no internet"
        deps = "brew deps --formula --installed --for-each timed out"
        self.inst.inventory_error = self.inv.inventory_error = f"{outdated}; {deps}"
        issues = self.detect()
        self.assertEqual(self.found("brew-degraded-inventory", issues), [])
        probe = self.only("brew-failed-probe")
        self.assertEqual((probe.severity, probe.blocks, probe.remedies), (Severity.INFO, (), []))
        self.assertEqual(probe.evidence, [f"{outdated}; {deps}",
                                          "the outdated packages come from brew info, without their current versions",
                                          "the dependencies come from the receipts and brew info alone"])


class OrderTest(HealthCase):
    """The table order of the findings, and the distinct action ids of two prefixes"""

    def test_findings_come_in_table_order(self):
        self.formula("wget", receipt=False, linked=False, pinned=True)
        self.inv.missing = {"wget": ["libidn2"]}
        codes = [i.code for i in self.detect()]
        self.assertEqual(codes, sorted(codes, key=list(health.TITLES).index))
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

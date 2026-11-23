"""The system and environment detectors, a positive and a negative case each, and the aggregation"""

import os
import sys
import unittest
from unittest import mock

from brew_ports import doctor, doctor_report, model, runner as r, system
from brew_ports.model import Blocks, Manager, Severity
from tests.unit.fixtures.doctor import builders as b
from tests.unit.helpers import TempDirTest, make_instance, make_package


def codes(issues):
    """Return the names of findings

    @param issues  the findings
    @returns       their names, in order
    """
    return [i.code for i in issues]


class DetectorTest(TempDirTest):
    """The detectors' setting: a Homebrew and a MacPorts instance under the test directory, and a fake runner"""

    def setUp(self):
        super().setUp()
        # The test /tmp is a small tmpfs, so low disk space is tested on its own.
        space = mock.patch("brew_ports.system.free_bytes", return_value=100 * doctor.GIB)
        space.start()
        self.addCleanup(space.stop)
        self.brew = self.instance(Manager.BREW, "opt/homebrew")
        self.ports = self.instance(Manager.PORTS, "opt/local")
        self.runner = r.FakeRunner(default=b.NOT_FOUND, console=b.QuietConsole(), environ={"HOME": "/Users/alice"},
                                   out_dir=self.path("out"))

    def instance(self, manager, rel, **kw):
        """Return an instance whose prefix exists under the test directory

        @param manager  the instance's manager
        @param rel      the prefix, relative to the test directory
        @param kw       more `Instance` fields
        @returns        the instance, with the identity of its prefix
        """
        prefix = self.path(*rel.split("/"))
        os.makedirs(prefix, exist_ok=True)
        return make_instance(manager, prefix, identity=system.identity(prefix), spellings=(prefix,),
                             owned_roots=(prefix,), **kw)

    def linkage(self, cls, resolved, kind="formula", name="vim", prefix=None):
        """Return a linkage scan of one binary with one reference

        @param cls       the reference's class, such as `other`, `missing` or `own`
        @param resolved  the path the reference resolves to
        @param kind      the kind of the package that owns the binary
        @param name      that package's name
        @param prefix    the binary's instance prefix; None for the Homebrew one
        @returns         the scan
        """
        prefix = prefix or self.brew.prefix
        binary = os.path.join(prefix, "Cellar", name, "9.1", "bin", name)
        ref = {"name": resolved, "command": "LC_LOAD_DYLIB", "resolved": resolved, "class": cls}
        return {"binaries": {binary: {"package": f"{prefix}|{kind}|{name}", "instance_prefix": prefix,
                                      "archs": [], "references": [ref], "error": None}}}

    def entry(self, text, prefix=None, exists=True):
        """Return a PATH entry of the environment analysis

        @param text    the entry, also its path
        @param prefix  the instance it lies in, or None
        @param exists  whether its directory exists
        @returns       the entry
        """
        return {"text": text, "path": text, "instance_prefix": prefix, "exists": exists, "usr_local": False}

    def detect_system(self, **kw):
        """Return the system findings of a bundle, which holds only the Homebrew instance unless `kw` says

        @param kw  the bundle's parts
        @returns   the findings
        """
        kw.setdefault("instances", [self.brew])
        return doctor.system_issues(b.bundle(**kw), self.runner)

    def detect_env(self, **kw):
        """Return the environment findings of a bundle, which holds both instances unless `kw` says

        @param kw  the bundle's parts
        @returns   the findings
        """
        kw.setdefault("instances", [self.brew, self.ports])
        return doctor.env_issues(b.bundle(**kw), self.runner)

    def only(self, issues, code):
        """Return the findings of one name

        @param issues  the findings
        @param code    the name to keep
        @returns       the matching findings, in order
        """
        return [i for i in issues if i.code == code]


class SystemTest(DetectorTest):
    """The `system-*` detectors"""

    def test_clt_missing_or_without_receipt(self):
        found = self.only(self.detect_system(system={"developer_dir": None}), "system-clt-missing")
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].severity, found[0].blocks), (Severity.HIGH, (Blocks.ANY,)))
        self.assertTrue(all(a.manual for a in found[0].remedies))
        self.assertEqual(found[0].remedies[0].argv, [system.XCODE_SELECT, "--install"])
        self.assertEqual(codes(self.detect_system(system={"clt_receipt": False})), ["system-clt-missing"])
        self.assertEqual(self.detect_system(), [])

    def test_xcode_licence(self):
        found = self.detect_system(system={"developer_dir": "/Applications/Xcode.app/Contents/Developer",
                                           "xcode_license_ok": False})
        self.assertEqual(codes(found), ["system-xcode-license"])
        self.assertTrue(found[0].remedies[0].sudo and found[0].remedies[0].manual)
        self.assertEqual(self.detect_system(system={"xcode_license_ok": True}), [])

    def test_root_or_sudo(self):
        self.runner.environ["SUDO_USER"] = "alice"
        found = self.only(self.detect_system(), "system-running-as-root")
        self.assertEqual(found[0].severity, Severity.CRITICAL)
        del self.runner.environ["SUDO_USER"]
        self.assertEqual(self.only(self.detect_system(), "system-running-as-root"), [])

    def test_python_or_tool_inside_a_prefix(self):
        python = os.path.join(self.brew.prefix, "opt", "python@3.15", "bin", "python3.15")
        found = self.only(self.detect_system(system={"python_path": python}), "system-running-inside-prefix")
        self.assertEqual([(i.severity, i.subject, i.instance_prefix, i.blocks) for i in found],
                         [(Severity.CRITICAL, python, self.brew.prefix, (Blocks.ANY,))])
        tool = os.path.join(self.ports.prefix, "share", "brew-ports", "lib", "brew-ports.pyz")
        found = self.detect_system(instances=[self.brew, self.ports], system={"tool_path": tool})
        self.assertEqual([(i.code, i.instance_prefix) for i in found],
                         [("system-running-inside-prefix", self.ports.prefix)])
        outside = self.path("bundle", "python", "bin", "python3")
        self.assertEqual(self.detect_system(system={"python_path": outside, "tool_path": outside}), [])

    def test_a_spelling_alone_never_places_the_python(self):
        gone = self.path("gone", "homebrew")
        spelled = make_instance(Manager.BREW, gone, identity=(1, 2), spellings=(gone,), owned_roots=(gone,))
        python = os.path.join(gone, "bin", "python3")
        self.assertEqual(self.detect_system(instances=[spelled], system={"python_path": python}), [])

    def test_less_than_five_gib_free(self):
        with mock.patch("brew_ports.system.free_bytes", return_value=2 * doctor.GIB):
            found = self.detect_system()
        self.assertEqual(codes(found), ["system-low-disk-space"])
        self.assertEqual((found[0].subject, found[0].blocks), (self.brew.prefix, (Blocks.ANY,)))
        self.assertEqual(found[0].title, f"Only 2.0 GiB is free on the disk of Homebrew at {self.brew.prefix}; a move "
                                         "needs 5")
        with mock.patch("brew_ports.system.free_bytes", return_value=50 * doctor.GIB):
            self.assertEqual(self.detect_system(), [])

    def test_rosetta_shell(self):
        found = self.detect_system(system={"translated": True})
        self.assertEqual([(i.code, i.severity) for i in found], [("system-rosetta-shell", Severity.INFO)])
        self.assertEqual(self.detect_system(system={"translated": False}), [])

    def test_dyld_exports_in_shell_files(self):
        rec = {"kind": "dyld", "file": "/Users/alice/.zshrc", "lineno": 4, "var": "DYLD_INSERT_LIBRARIES",
               "text": "export DYLD_INSERT_LIBRARIES=/x.dylib", "instance_prefixes": []}
        found = self.detect_system(environment={"records": [rec]})
        self.assertEqual(codes(found), ["system-dyld-export"])
        self.assertEqual(found[0].subject, "/Users/alice/.zshrc:4")
        self.assertEqual(found[0].title, "/Users/alice/.zshrc line 4 sets a DYLD_ variable, which changes the "
                                         "libraries every program loads")
        self.assertTrue(found[0].remedies[0].description.startswith("Fix: remove the line unless"))
        self.assertEqual(self.detect_system(environment={"records": [dict(rec, kind="assign")]}), [])

    def test_a_library_path_into_an_installation_is_one_finding(self):
        rec = {"kind": "dyld", "file": "/Users/alice/.zshrc", "lineno": 4, "var": "DYLD_LIBRARY_PATH",
               "text": "export DYLD_LIBRARY_PATH=/opt/local/lib", "instance_prefixes": [self.ports.prefix]}
        environment = {"records": [rec]}
        self.assertEqual(self.detect_system(environment=environment), [])
        found = self.detect_env(environment=environment)
        self.assertEqual([i.title for i in found], [
            "/Users/alice/.zshrc line 4 makes every program load libraries from MacPorts at " + self.ports.prefix])


class EnvTest(DetectorTest):
    """The `env-*` detectors"""

    def test_both_managers_with_packages(self):
        pkgs = [make_package("wget", prefix=self.brew.prefix),
                make_package("curl", kind="port", prefix=self.ports.prefix)]
        found = self.detect_env(packages=pkgs)
        self.assertEqual(codes(found), ["env-both-managers"])
        self.assertEqual(found[0].evidence, [f"Homebrew at {self.brew.prefix}: 1 formula",
                                             f"MacPorts at {self.ports.prefix}: 1 port"])
        self.assertEqual(self.detect_env(packages=pkgs[:1]), [])

    def test_shadowed_commands(self):
        shadowed = [{"command": "git", "winner": self.brew.prefix + "/bin/git",
                     "prefixes": [self.brew.prefix, self.ports.prefix]}]
        found = self.detect_env(environment={"shadowed": shadowed})
        self.assertEqual(codes(found), ["env-shadowed-commands"])
        self.assertEqual((found[0].title, found[0].evidence), (
            "1 command exists in more than one installation",
            [f"Typing one runs the copy of Homebrew at {self.brew.prefix}: git"]))
        self.assertEqual(self.detect_env(environment={"shadowed": []}), [])

    def test_cross_prefix_linkage_offers_a_rebuild(self):
        found = self.detect_env(linkage=self.linkage("other", self.ports.prefix + "/lib/libz.1.dylib"),
                                packages=[make_package("vim", prefix=self.brew.prefix)])
        self.assertEqual(codes(found), ["env-cross-prefix-linkage"])
        issue = found[0]
        self.assertEqual((issue.subject, issue.instance_prefix, issue.confirm_each, issue.auto_fix),
                         ("vim", self.brew.prefix, True, False))
        self.assertEqual(issue.remedies[0].argv[-3:], ["reinstall", "--formula", "vim"])
        self.assertEqual(issue.remedies[0].action_id, "doctor.env-cross-prefix-linkage.vim.reinstall")
        self.assertEqual(doctor.removes_package(issue), ("formula", "vim"))

    def vim_port(self):
        """Return the active vim port of the MacPorts instance, installed with a variant

        @returns  a list of that one package
        """
        return [make_package("vim", kind="port", prefix=self.ports.prefix, requested_variants=["+huge"],
                             spec_args=["vim", "@9.1_0+huge"])]

    def test_port_rebuild_is_a_forced_upgrade(self):
        link = self.linkage("missing", self.brew.prefix + "/opt/gettext/lib/libintl.8.dylib", kind="port",
                            prefix=self.ports.prefix)
        issue = self.only(self.detect_env(linkage=link, packages=self.vim_port()), "env-cross-prefix-linkage")[0]
        action = issue.remedies[0]
        self.assertTrue(action.sudo)
        self.assertIn("--force", action.argv)
        self.assertIn("-t", action.argv)                          # a Homebrew instance exists
        self.assertEqual(action.retry_argv[-2:], ["vim", "+huge"])
        self.assertEqual(doctor.removes_package(issue), ("port", "vim"))

    def test_missing_file_in_its_own_prefix_is_ignored(self):
        # That is broken linkage within one prefix, not a cross-prefix reference.
        own = self.linkage("missing", self.ports.prefix + "/lib/libgone.dylib", kind="port", prefix=self.ports.prefix)
        found = self.detect_env(linkage=own, packages=self.vim_port())
        self.assertEqual(self.only(found, "env-cross-prefix-linkage"), [])

    def test_cross_linkage_negative_and_undrivable(self):
        self.assertEqual(self.detect_env(linkage=self.linkage("own", self.brew.prefix + "/lib/libx.dylib")), [])
        self.assertEqual(self.detect_env(linkage=self.linkage("system", "/usr/lib/libSystem.B.dylib")), [])
        self.brew.drivable = False
        issue = self.detect_env(linkage=self.linkage("usrlocal", "/usr/local/lib/libfoo.dylib"))[0]
        self.assertFalse(issue.confirm_each)
        self.assertTrue(all(a.manual for a in issue.remedies))

    def test_local_builds(self):
        found = self.detect_env(packages=[make_package("vim", prefix=self.brew.prefix, built_locally=True)])
        self.assertEqual([(i.code, i.subject) for i in found], [("env-local-builds", self.brew.prefix)])
        self.assertEqual(self.detect_env(packages=[make_package("vim", prefix=self.brew.prefix)]), [])

    def test_dyld_library_path_naming_a_prefix(self):
        rec = {"kind": "dyld", "file": "/Users/alice/.zshrc", "lineno": 2, "var": "DYLD_LIBRARY_PATH",
               "text": f"export DYLD_LIBRARY_PATH={self.brew.prefix}/lib", "instance_prefixes": [self.brew.prefix]}
        live = {"DYLD_FALLBACK_LIBRARY_PATH": [self.entry(self.ports.prefix + "/lib", self.ports.prefix)]}
        found = self.only(self.detect_env(environment={"records": [rec], "live": live}), "env-dyld-library-path")
        self.assertEqual([(i.subject, i.instance_prefix, i.severity) for i in found],
                         [("/Users/alice/.zshrc:2", self.brew.prefix, Severity.HIGH),
                          ("DYLD_FALLBACK_LIBRARY_PATH", self.ports.prefix, Severity.HIGH)])
        quiet = dict(rec, instance_prefixes=[])
        self.assertEqual(self.only(self.detect_env(environment={"records": [quiet]}), "env-dyld-library-path"), [])

    def test_build_variables_naming_the_other_prefix(self):
        rec = {"kind": "build", "file": "/Users/alice/.zprofile", "lineno": 7, "var": "PKG_CONFIG_PATH",
               "text": f"export PKG_CONFIG_PATH={self.brew.prefix}/lib/pkgconfig",
               "instance_prefixes": [self.brew.prefix]}
        found = self.detect_env(environment={"records": [rec]})
        self.assertEqual([(i.code, i.instance_prefix) for i in found], [("env-build-variables", self.brew.prefix)])
        live = {"LDFLAGS": [self.entry(self.ports.prefix + "/lib", self.ports.prefix)]}
        self.assertEqual([i.subject for i in self.detect_env(environment={"live": live})], ["LDFLAGS"])
        # With one manager there is no other prefix to leak into.
        self.assertEqual(self.detect_env(instances=[self.brew], environment={"records": [rec]}), [])

    def tool(self, inst, name):
        """Write an executable script into an instance's `bin`

        @param inst  the instance
        @param name  the command's name
        @returns     the script's path
        """
        path = os.path.join(inst.prefix, "bin", name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\n")
        os.chmod(path, 0o755)
        return path

    def test_split_interpreters(self):
        self.tool(self.brew, "python3")
        self.tool(self.ports, "pip3")
        live = {"PATH": [self.entry(self.brew.prefix + "/bin"), self.entry(self.ports.prefix + "/bin")]}
        found = self.detect_env(environment={"live": live})
        self.assertEqual([(i.code, i.subject) for i in found], [("env-split-interpreters", "python3/pip3")])
        self.assertIn(self.brew.prefix, found[0].evidence[0])
        self.tool(self.brew, "pip3")
        self.assertEqual(self.detect_env(environment={"live": live}), [])

    def test_language_packages(self):
        extras = {"npm": [{"name": "typescript", "version": "5.4", "instance_prefix": self.brew.prefix}],
                  "python": [{"version": "3.12", "instance_prefix": None, "site_packages": "/Users/alice/site",
                              "dists": [{"name": "requests", "version": "2.31"}]}],
                  "pipx": [], "gems": [], "cpan": []}
        found = self.detect_env(extras=extras)
        # One finding per place, with counts: the names are in the lists of the run folder.
        self.assertEqual([(i.code, i.subject, i.severity, i.title, i.evidence) for i in found], [
            ("env-language-packages", "home", Severity.INFO, "Your home folder holds packages that pip installed",
             ["Python 3.12: 1"]),
            ("env-language-packages", self.brew.prefix, Severity.MEDIUM, f"Homebrew at {self.brew.prefix} holds "
             "packages that npm installed; a move does not move them", ["npm packages: 1"])])
        self.assertIn("for you to install them again after a move", found[1].remedies[0].description)
        self.assertEqual(self.detect_env(extras={"python": [{"version": "3.12", "dists": []}], "npm": []}), [])

    def test_services_from_both_managers(self):
        svcs = [b.service("sh.brew.mysql", "/a.plist", self.brew.prefix, "mysql", data_dirs=["/d1"]),
                b.service("org.macports.redis", "/b.plist", self.ports.prefix, "redis", kind="port",
                          scope="system", data_dirs=["/d2"])]
        found = self.detect_env(services=svcs)
        self.assertEqual(codes(found), ["env-services-of-both"])
        self.assertEqual(len(found[0].evidence), 2)
        self.assertEqual(self.detect_env(services=svcs[:1]), [])

    def test_duplicate_or_dead_path_entries(self):
        live = {"PATH": [self.entry("/usr/bin"), self.entry("/gone/bin", exists=False)]}
        rec = {"kind": "assign", "file": "/Users/alice/.zshrc", "lineno": 3, "var": "PATH",
               "entries": [self.entry("/nowhere/bin", exists=False)]}
        found = self.detect_env(environment={"live": live, "live_duplicates": {"PATH": ["/usr/bin"]},
                                             "records": [rec]})
        self.assertEqual(codes(found), ["env-dead-path-entries"])
        self.assertEqual(len(found[0].evidence), 3)
        self.assertEqual(self.detect_env(environment={"live": {"PATH": [self.entry("/usr/bin")]}}), [])

    def test_etc_paths_for_a_prefix(self):
        lines = [{"file": "/etc/paths.d/macports", "lineno": 1, "stock": False,
                  "entry": self.entry(self.ports.prefix + "/bin", self.ports.prefix)},
                 {"file": "/etc/paths", "lineno": 1, "stock": True,
                  "entry": self.entry("/usr/local/bin", "/usr/local")}]
        found = self.detect_env(environment={"etc_paths": lines})
        self.assertEqual([(i.code, i.subject) for i in found], [("env-etc-paths", "/etc/paths.d/macports:1")])
        self.assertEqual(self.detect_env(environment={"etc_paths": lines[1:]}), [])

    def test_gui_path_names_a_prefix(self):
        gui = [self.entry(self.brew.prefix + "/bin", self.brew.prefix), self.entry("/usr/bin")]
        found = self.detect_env(environment={"gui_path": gui})
        self.assertEqual(codes(found), ["env-gui-path"])
        self.assertEqual(found[0].remedies[0].argv[-1], "/usr/bin")
        self.assertTrue(found[0].remedies[0].manual and found[0].remedies[0].sudo)
        self.assertEqual(self.detect_env(environment={"gui_path": gui[1:]}), [])

    def test_shell_markers(self):
        recs = [{"kind": "marker", "file": "/Users/alice/.zprofile", "lineno": 9,
                 "text": "# MacPorts Installer addition"},
                {"kind": "shellenv", "file": "/Users/alice/.zprofile", "lineno": 1, "text": "eval ..."}]
        found = self.detect_env(environment={"records": recs})
        self.assertEqual(codes(found), ["env-shell-markers"])
        self.assertEqual(found[0].title, "2 lines of /Users/alice/.zprofile set up Homebrew or MacPorts")
        self.assertEqual(found[0].evidence[0], "/Users/alice/.zprofile line 1: eval ...")
        self.assertEqual(self.detect_env(environment={"records": []}), [])

    def test_users_own_launchd_job(self):
        svc = b.service("com.alice.backup", "/Users/alice/Library/LaunchAgents/com.alice.backup.plist",
                        self.brew.prefix, owned=False, program=self.brew.prefix + "/bin/rsync")
        found = self.detect_env(services=[svc])
        self.assertEqual([(i.code, i.subject, i.remedies[0].manual) for i in found],
                         [("env-user-launchd-job", svc.plist, True)])
        self.assertIn("rsync", found[0].evidence[0])
        self.assertEqual(self.detect_env(services=[b.service("sh.brew.x", "/p", self.brew.prefix, "x")]), [])

    def test_login_shell_from_a_prefix(self):
        environment = {"login_shell": self.brew.prefix + "/bin/fish", "login_shell_prefix": self.brew.prefix}
        found = self.detect_env(environment=environment)
        self.assertEqual([(i.code, i.severity, i.instance_prefix) for i in found],
                         [("env-login-shell", Severity.HIGH, self.brew.prefix)])
        self.assertEqual(self.detect_env(environment={"login_shell": "/bin/zsh", "login_shell_prefix": None}), [])

    def test_shell_file_sources_from_a_prefix(self):
        rec = {"kind": "source", "file": "/Users/alice/.zshrc", "lineno": 12, "brew": None,
               "text": f"source {self.brew.prefix}/share/zsh-autosuggestions/zsh-autosuggestions.zsh",
               "instance_prefixes": [self.brew.prefix]}
        by_name = dict(rec, lineno=13, brew="", instance_prefixes=[], text='source "$(brew --prefix)/x.zsh"')
        found = self.detect_env(environment={"records": [rec, by_name]})
        self.assertEqual([(i.code, i.subject, i.instance_prefix) for i in found],
                         [("env-sourced-files", "/Users/alice/.zshrc:12", self.brew.prefix),
                          ("env-sourced-files", "/Users/alice/.zshrc:13", None)])
        self.assertEqual(self.detect_env(environment={"records": [dict(rec, instance_prefixes=[])]}), [])


class AggregationTest(DetectorTest):
    """All the findings together, the dispatch to the health modules, and the text report"""

    def test_detect_all_merges_sorts_and_leaves_one_rebuild(self):
        broken = doctor._issue("brew-broken-linkage", Severity.HIGH, "Broken linkage", "vim", self.brew.prefix,
                               remedies=[r_action("doctor.brew-broken-linkage.vim.reinstall")], confirm_each=True)
        inactive = doctor._issue("ports-inactive-versions", Severity.LOW, "Inactive versions", "curl",
                                 self.ports.prefix)
        link = self.linkage("other", self.ports.prefix + "/lib/libz.1.dylib")
        bundle = b.bundle(instances=[self.brew, self.ports], linkage=link, system={"translated": True},
                          packages=[make_package("vim", prefix=self.brew.prefix)])
        with mock.patch.dict(sys.modules, b.health_modules(brew=[broken], ports=[inactive])):
            issues = doctor.detect_all(bundle, self.runner)
        self.assertEqual(codes(issues), ["brew-broken-linkage", "env-cross-prefix-linkage", "ports-inactive-versions",
                                         "system-rosetta-shell"])
        cross = issues[1]
        self.assertFalse(cross.confirm_each)
        self.assertEqual([a.kind for a in cross.remedies], ["note"])
        self.assertEqual(cross.remedies[0].description,
                         "The fix of the other finding about vim installs vim again, which mends this too.")

    def test_dispatch_to_the_health_modules(self):
        code = "brew-deleted-formula"
        issue = doctor._issue(code, Severity.MEDIUM, "Keg of a deleted formula", "old", self.brew.prefix)
        mods = b.health_modules(brew_terminal=[code], brew_removes={code: ("formula", "old")},
                                brew_verified={code: True})
        with mock.patch.dict(sys.modules, mods):
            self.assertTrue(doctor.needs_terminal_answer(issue))
            self.assertEqual(doctor.removes_package(issue), ("formula", "old"))
            self.assertTrue(doctor.verify(issue, self.runner, b.bundle()))
        own = doctor._issue("system-clt-missing", Severity.HIGH, "x")
        self.assertFalse(doctor.needs_terminal_answer(own))
        self.assertIsNone(doctor.removes_package(own))
        self.assertIsNone(doctor.verify(own, self.runner, b.bundle()))

    def test_the_health_modules_offer_the_agreed_functions(self):
        for family in ("brew", "ports"):
            module = doctor.health_module(family)
            for name in ("detect", "needs_terminal_answer", "removes_package", "verify"):
                self.assertTrue(callable(getattr(module, name, None)), f"{module.__name__}.{name}")
            self.assertEqual(module.detect(b.bundle(), self.runner), [])
        ports = doctor.health_module("ports")
        self.assertTrue(callable(ports.manager_repair))
        self.assertTrue(set(ports.MANAGER_REPAIRS) <= {"ports-platform-mismatch", "ports-built-for-other-os",
                                                       "ports-registry-schema-update", "ports-cannot-run",
                                                       "ports-no-registry"})

    def test_render_groups_by_severity_and_lists_what_blocks(self):
        issues = doctor.sort_issues([
            doctor._issue("env-dead-path-entries", Severity.LOW, "Duplicate or dead PATH entries", "PATH"),
            doctor._issue("system-clt-missing", Severity.HIGH, "Command Line Tools missing", None, None,
                          evidence=["evidence"],
                          remedies=[doctor.manual("system-clt-missing", None, "install",
                                                  ["/usr/bin/xcode-select", "--install"], "x")])])
        lines = doctor_report.render(issues, [])
        self.assertIn("      x: /usr/bin/xcode-select --install", lines)
        self.assertLess(lines.index("Broken or at risk (1)"), lines.index("Worth cleaning up (1)"))
        self.assertEqual(doctor_report.render([], [])[-1], "No problems found.")
        self.assertEqual(doctor.findings_exit(issues), 1)
        self.assertEqual(doctor.findings_exit([doctor._issue("env-local-builds", Severity.INFO, "x")]), 0)


def r_action(action_id):
    """Return a remedy that runs `brew reinstall vim` under the brew profile

    @param action_id  the action's id
    @returns          the action
    """
    return model.Action(action_id=action_id, kind="command", argv=["/opt/homebrew/bin/brew", "reinstall", "vim"],
                        sudo=False, description="reinstall", env_profile="brew")


if __name__ == "__main__":
    unittest.main()

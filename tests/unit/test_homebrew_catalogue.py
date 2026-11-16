"""The offline Homebrew catalogue: lookups, lifecycle dates, loading and the cask artifact rules"""

import datetime
import json
import os
import unittest
from typing import Any
from unittest import mock

from brew_ports.homebrew import catalogue as cat, locate
from tests.unit.helpers import TempDirTest, make_instance
from tests.unit.test_homebrew_support import (TODAY, fixture_catalogue, install_api, payload, root_owned_lstat,
                                              symlink, write)

D = datetime.date


class LookupTest(unittest.TestCase):
    """Name lookups, entries, executables, homepages, service labels and casks of the fixture catalogue"""

    def setUp(self):
        self.c = fixture_catalogue()

    def test_names_from_payload_and_name_files(self):
        names = self.c.formula_names()
        self.assertIn("wget", names)
        self.assertIn("cython", names)          # formula_names.txt only
        self.assertIn("firefox", self.c.cask_tokens())
        self.assertEqual(self.c.source, "api")
        self.assertFalse(self.c.degraded)

    def test_canonical_follows_aliases_and_renames(self):
        self.assertEqual(self.c.canonical("wget"), "wget")
        self.assertEqual(self.c.canonical("gsed"), "gnu-sed")
        self.assertEqual(self.c.canonical("openssl"), "openssl@3")       # formula_aliases.txt
        self.assertEqual(self.c.canonical("openssl@3.5"), "openssl@3")   # payload alias
        self.assertEqual(self.c.canonical("act_runner"), "gitea-runner")  # formula_renames
        self.assertEqual(self.c.canonical("glib-utils"), "glib")         # oldnames
        self.assertIsNone(self.c.canonical("no-such-formula"))
        self.assertEqual(self.c.canonical("docker"), "docker")
        self.assertEqual(self.c.canonical("docker", "cask"), "docker-desktop")
        self.assertIsNone(self.c.canonical("wget", "cask"))
        self.assertTrue(self.c.knows("rg"))

    def test_rename_alias_and_migration_lookups(self):
        self.assertEqual(self.c.renamed_to("act_runner"), "gitea-runner")
        self.assertIsNone(self.c.renamed_to("wget"))
        self.assertEqual(self.c.renamed_to("docker", "cask"), "docker-desktop")
        self.assertEqual(self.c.alias_target("gsed"), "gnu-sed")
        self.assertEqual(self.c.tap_migration("android-ndk"), "homebrew/cask")
        self.assertEqual(self.c.tap_migration("basex", "cask"), "homebrew/core")
        self.assertIsNone(self.c.tap_migration("wget"))

    def test_entries(self):
        self.assertEqual(self.c.formula("gsed"), self.c.formula("gnu-sed"))
        self.assertEqual(self.c.version("wget"), "1.25.0_2")
        self.assertEqual(self.c.version("jq"), payload()["formulae"]["jq"]["stable_version"])
        self.assertEqual(self.c.version("0-ad", "cask"), "0.28.0")
        self.assertEqual(self.c.homepage("wget"), "https://www.gnu.org/software/wget/")
        self.assertEqual(self.c.desc("docker-desktop", "cask")[:3], "App")
        self.assertTrue(self.c.keg_only("postgresql@16"))
        self.assertFalse(self.c.keg_only("wget"))
        self.assertFalse(self.c.keg_only("cython"))
        self.assertTrue(self.c.has_bottle("wget"))
        self.assertTrue(self.c.has_bottle("gnu-sed"))      # relocatable: no bottle_cellar
        self.assertIsNone(payload()["formulae"]["gnu-sed"].get("bottle_cellar"))
        self.assertFalse(self.c.has_bottle("acl"))
        self.assertIsNone(self.c.formula("no-such-formula"))

    def test_python_dependencies_whatever_their_tags(self):
        deps = payload()["formulae"]["numpy"]["stable_dependencies"]
        expected = [n for d in deps for n in ([d] if isinstance(d, str) else list(d)) if n.startswith("python@3.")]
        self.assertGreaterEqual(len(expected), 2)
        self.assertEqual(self.c.python_dependencies("numpy"), expected)
        self.assertEqual(self.c.python_dependencies("wget"), [])
        self.assertEqual(self.c.python_dependencies("no-such-formula"), [])

    def test_executables(self):
        self.assertIn("jq", self.c.executables("jq"))
        self.assertEqual(self.c.executables("ripgrep"), ["rg"])            # executables.txt only
        self.assertEqual(self.c.by_executable("rg"), ["ripgrep"])
        self.assertEqual(self.c.by_executable("gsed"), ["gnu-sed"])
        self.assertIn("dbus", self.c.by_executable("dbus-daemon"))
        self.assertEqual(self.c.by_executable("no-such-tool"), [])

    def test_homepage_index_normalises_urls(self):
        self.assertEqual(self.c.by_homepage("http://gnu.org/software/wget"), [("formula", "wget")])
        self.assertEqual(self.c.by_homepage("https://www.docker.com/products/docker-desktop/#top"),
                         [("cask", "docker-desktop")])
        self.assertEqual(self.c.by_homepage("https://example.invalid/"), [])
        self.assertEqual(cat.normalise_url("HTTP://WWW.Example.COM/Path/"), "https://example.com/Path")
        self.assertIsNone(cat.normalise_url(None))

    def test_service_labels(self):
        labels = self.c.service_labels()
        self.assertEqual(labels["sh.brew.wget"], "wget")
        self.assertEqual(labels["homebrew.mxcl.wget"], "wget")
        self.assertEqual(labels["sh.brew.cython"], "cython")
        self.assertEqual(labels["org.freedesktop.dbus-session"], "dbus")
        self.assertEqual(labels["homebrew.mxcl.startx"], "xinit")

    def test_a_renamed_formula_keeps_the_labels_of_its_old_name(self):
        labels = self.c.service_labels()
        self.assertEqual(labels["homebrew.mxcl.act_runner"], "gitea-runner")   # formula_renames
        self.assertEqual(labels["sh.brew.glib-utils"], "glib")                 # oldnames
        self.assertNotIn("sh.brew.alloy", labels)                              # renamed to no catalogue formula
        self.assertNotIn("homebrew.mxcl.gsed", labels)                         # an alias names no job

    def test_explicit_label_wins_over_a_generated_one(self):
        c = cat.Catalogue(formulae={"startx": {}, "xinit": {"service_name_args": {":macos": "homebrew.mxcl.startx"}}},
                          source="api")
        self.assertEqual(c.service_labels()["homebrew.mxcl.startx"], "xinit")

    def test_cask_info(self):
        aptible = self.c.cask("aptible")
        self.assertEqual(aptible.depends_formula, ["libfido2"])
        self.assertEqual((aptible.privileged_install, aptible.privileged_uninstall), (True, True))
        self.assertEqual(self.c.cask("ace-link").depends_cask, ["docker"])
        self.assertEqual(self.c.cask("docker").token, "docker-desktop")
        self.assertTrue(self.c.cask("docker-desktop").auto_updates)
        self.assertIsNone(self.c.cask("no-such-cask"))
        bepo = self.c.cask("bepo")
        self.assertEqual((bepo.privileged_install, bepo.privileged_uninstall), (True, True))
        # The kicad demos go to /Library/Application Support/kicad, which the user cannot write.
        kicad = self.c.cask("kicad")
        self.assertEqual((kicad.privileged_install, kicad.privileged_uninstall), (True, True))


class PlainAppCaskTest(TempDirTest):
    """A plain app cask in a directory the user can write, which needs no sudo"""

    def test_app_in_a_writable_directory_needs_no_sudo(self):
        apps = self.path("Applications")
        os.makedirs(apps)
        patcher = mock.patch.object(cat, "LAUNCH_DAEMONS", self.path("LaunchDaemons"))
        patcher.start()
        self.addCleanup(patcher.stop)
        c = fixture_catalogue(appdir=apps, home=self.tmp)
        info = c.cask("0-ad")
        self.assertEqual((info.privileged_install, info.privileged_uninstall), (False, False))
        self.assertFalse(info.auto_updates)
        info = c.cask("appcleaner")
        self.assertEqual((info.privileged_install, info.privileged_uninstall), (False, False))


class LifecycleTest(unittest.TestCase):
    """Deprecation, disabling and refusal by date, as Homebrew evaluates them"""

    def entry(self, deprecate=None, disable=None, **disable_extra):
        """Build a catalogue entry with the `deprecate_args` and `disable_args` of the dates given

        @param deprecate      the deprecation date, or None for no `deprecate_args`
        @param disable        the disable date, or None for no `disable_args`
        @param disable_extra  further `disable_args` keys, such as `:replacement_formula`
        @returns              the entry
        """
        e = {}
        if deprecate:
            e["deprecate_args"] = {":date": deprecate, ":because": ":unmaintained"}
        if disable:
            e["disable_args"] = dict({":date": disable, ":because": ":unmaintained"}, **disable_extra)
        return e

    def test_date_table(self):
        past, ahead = "2026-01-01", "2027-01-01"
        cases = [
            ((None, None), (False, False)),
            ((past, None), (True, False)),
            ((ahead, None), (False, False)),
            ((None, past), (False, True)),
            ((None, ahead), (True, False)),
            ((past, past), (True, True)),
            ((ahead, past), (False, True)),
            ((past, ahead), (True, False)),
            ((ahead, ahead), (False, False)),
            (("2026-11-12", None), (True, False)),
            ((None, "2026-11-12"), (False, True)),
            ((None, "2026-11-13"), (True, False)),
        ]
        for (deprecate, disable), expected in cases:
            with self.subTest(deprecate=deprecate, disable=disable):
                self.assertEqual(cat.lifecycle(self.entry(deprecate, disable), TODAY), expected)

    def test_future_disable_date_deprecates_a_cask(self):
        both_ahead = self.entry("2027-01-01", "2027-06-01")
        self.assertEqual(cat.lifecycle(both_ahead, TODAY, "formula"), (False, False))
        self.assertEqual(cat.lifecycle(both_ahead, TODAY, "cask"), (True, False))
        self.assertEqual(cat.lifecycle(self.entry("2027-01-01", "2026-01-01"), TODAY, "cask"), (False, True))

    def test_refused_formulae_and_casks_from_the_fixture(self):
        c = fixture_catalogue()
        # aamath: deprecated 2026-07-17, disabled from 2027-01-05.
        self.assertTrue(c.deprecated("aamath"))
        self.assertIsNone(c.refused("aamath"))
        # apophenia: disable date passed, no deprecate_args: refused.
        refused = c.refused("apophenia")
        self.assertEqual(refused["date"], "2026-05-16")
        self.assertIn("gsl", refused["because"])
        self.assertIsNone(refused["replacement_formula"])
        self.assertFalse(c.deprecated("apophenia"))
        self.assertTrue(c.disabled("apophenia"))
        # Both dates passed: installs with a warning.
        self.assertTrue(c.deprecated("aescrypt-packetizer"))
        self.assertTrue(c.disabled("aescrypt-packetizer"))
        self.assertIsNone(c.refused("aescrypt-packetizer"))
        # Disable date ahead and no deprecate_args: deprecated until that date, refused after it.
        self.assertTrue(c.deprecated("docker-machine-driver-vmware"))
        self.assertIsNone(c.refused("docker-machine-driver-vmware"))
        later = fixture_catalogue(today=D(2027, 6, 30))
        self.assertEqual(later.refused("docker-machine-driver-vmware")["because"], "deprecated_upstream")
        self.assertFalse(later.deprecated("docker-machine-driver-vmware"))
        # Only a deprecate date: passed or ahead.
        self.assertTrue(c.deprecated("detox"))
        self.assertFalse(c.deprecated("abricate"))
        # Both dates ahead: neither.
        self.assertFalse(c.deprecated("postgresql@16"))
        self.assertIsNone(c.refused("postgresql@16"))
        # Casks.
        self.assertEqual(c.refused("1kc-razer", "cask"),
                         {"date": "2026-09-01", "because": "fails_gatekeeper_check",
                          "replacement_formula": None, "replacement_cask": None})
        self.assertIsNotNone(c.refused("ace-link", "cask"))
        self.assertIsNone(fixture_catalogue(today=D(2026, 8, 31)).refused("ace-link", "cask"))
        self.assertTrue(c.deprecated("1password-cli@1", "cask"))
        self.assertIsNone(c.refused("1password-cli@1", "cask"))
        self.assertIsNone(c.refused("no-such-formula"))
        self.assertFalse(c.deprecated("no-such-formula"))

    def test_refused_names_the_replacement(self):
        c = cat.Catalogue(formulae={"oldthing": self.entry(None, "2026-01-01", **{":replacement_formula": "newthing"})},
                          source="api", today=TODAY)
        self.assertEqual(c.refused("oldthing"), {"date": "2026-01-01", "because": "unmaintained",
                                                 "replacement_formula": "newthing", "replacement_cask": None})


class LoadTest(TempDirTest):
    """Loading the catalogue: the per-arch API file, the tap-checkout fallback, the name files and cask options"""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(locate, "SYSTEM_BREW_ENV", self.path("etc", "homebrew", "brew.env"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.prefix = self.path("opt", "homebrew")
        os.makedirs(os.path.join(self.prefix, "Library", "Homebrew"))
        self.cache = self.path("cache")
        self.env = {"HOME": self.path("home")}

    def instance(self, arch="arm64"):
        """Return the test's Homebrew instance, its cache and repository in the temporary directory

        @param arch  the instance's architecture
        @returns     the instance
        """
        return make_instance(prefix=self.prefix, cache_dir=self.cache, arch=arch, repository=self.prefix)

    def write_api(self, tag, formulae, mtime):
        """Write a per-arch API file that holds the formulae given

        @param tag       the bottle tag, such as `arm64_sequoia`
        @param formulae  the payload's formulae by name
        @param mtime     the file's modification time
        @returns         the file's path
        """
        path = os.path.join(self.cache, "api", "internal", f"packages.{tag}.jws.json")
        write(path, json.dumps({"payload": json.dumps({"formulae": formulae, "casks": {}})}))
        os.utime(path, (mtime, mtime))
        return path

    def make_checkout(self):
        """Write homebrew-core and homebrew-cask tap checkouts: two formulae, an alias and a cask"""
        taps = os.path.join(self.prefix, "Library", "Taps", "homebrew")
        write(os.path.join(taps, "homebrew-core", "Formula", "a", "abc.rb"), "class Abc < Formula\nend\n")
        write(os.path.join(taps, "homebrew-core", "Formula", "zed.rb"), "class Zed < Formula\nend\n")
        symlink(os.path.join(taps, "homebrew-core", "Aliases", "abc2"), "../Formula/a/abc.rb")
        write(os.path.join(taps, "homebrew-cask", "Casks", "f", "foo.rb"), "cask \"foo\" do\nend\n")

    def test_newest_api_file_of_the_instance_arch(self):
        install_api(self.cache)
        tahoe = os.path.join(self.cache, "api", "internal", "packages.arm64_tahoe.jws.json")
        os.utime(tahoe, (2000, 2000))
        self.write_api("arm64_sequoia", {"sequoia-only": {}}, 1000)
        self.write_api("tahoe", {"intel-only": {}}, 3000)
        self.write_api("x86_64_linux", {"linux-only": {}}, 4000)
        arm = cat.Catalogue.load(self.instance("arm64"), self.env, today=TODAY)
        self.assertEqual(arm.api_file, tahoe)
        self.assertEqual(arm.api_mtime, 2000)
        self.assertIn("wget", arm.formula_names())
        self.assertEqual((arm.source, arm.degraded, arm.frozen), ("api", False, False))
        intel = cat.Catalogue.load(self.instance("x86_64"), self.env, today=TODAY)
        self.assertIsNotNone(intel.formula("intel-only"))
        self.assertIsNone(intel.formula("linux-only"))
        os.utime(os.path.join(self.cache, "api", "internal", "packages.arm64_sequoia.jws.json"), (5000, 5000))
        self.assertIsNotNone(cat.Catalogue.load(self.instance("arm64"), self.env).formula("sequoia-only"))

    def test_no_install_from_api_uses_the_tap_checkout(self):
        install_api(self.cache)
        self.make_checkout()
        c = cat.Catalogue.load(self.instance(), dict(self.env, HOMEBREW_NO_INSTALL_FROM_API="1"), today=TODAY)
        self.assertEqual((c.source, c.degraded, c.frozen), ("taps", True, True))
        self.assertEqual(c.formula_names(), frozenset({"abc", "zed"}))
        self.assertEqual(c.canonical("abc2"), "abc")
        self.assertEqual(c.cask_tokens(), frozenset({"foo"}))
        self.assertIsNone(c.homepage("abc"))
        self.assertEqual(c.executables("abc"), [])
        self.assertFalse(c.has_bottle("abc"))
        self.assertEqual(c.service_labels()["sh.brew.zed"], "zed")
        self.assertNotIn("wget", c.formula_names())

    def test_no_install_from_api_from_a_brew_env_file(self):
        install_api(self.cache)
        self.make_checkout()
        write(os.path.join(self.prefix, "etc", "homebrew", "brew.env"), "HOMEBREW_NO_INSTALL_FROM_API=1\n")
        self.assertEqual(cat.Catalogue.load(self.instance(), self.env).source, "taps")

    def test_absent_api_file_falls_back_to_the_checkout(self):
        self.make_checkout()
        c = cat.Catalogue.load(self.instance(), self.env)
        self.assertEqual((c.source, c.frozen), ("taps", False))

    def test_frozen_api_without_a_checkout_is_still_read(self):
        install_api(self.cache)
        c = cat.Catalogue.load(self.instance(), dict(self.env, HOMEBREW_NO_INSTALL_FROM_API="1"))
        self.assertEqual((c.source, c.frozen), ("api", True))
        self.assertIn("wget", c.formula_names())

    def test_name_files_alone_and_nothing_at_all(self):
        install_api(self.cache)
        os.unlink(os.path.join(self.cache, "api", "internal", "packages.arm64_tahoe.jws.json"))
        c = cat.Catalogue.load(self.instance(), self.env)
        self.assertEqual((c.source, c.degraded), ("names", True))
        self.assertTrue(c.knows("cython"))
        self.assertEqual(c.canonical("rg"), "ripgrep")
        self.assertEqual(c.by_executable("jq"), ["jq"])
        empty = cat.Catalogue.load(make_instance(prefix=self.prefix, cache_dir=self.path("none")), self.env)
        self.assertEqual(empty.source, "none")
        self.assertFalse(empty.knows("wget"))

    def test_corrupt_api_file_is_recorded(self):
        write(os.path.join(self.cache, "api", "internal", "packages.arm64_tahoe.jws.json"), "{not json")
        c = cat.Catalogue.load(self.instance(), self.env)
        self.assertIn("packages.arm64_tahoe.jws.json", c.load_error or "")
        self.assertTrue(c.degraded)

    def test_cask_dirs_follow_homebrew_cask_opts(self):
        opts = "--appdir=~/Apps --fontdir /Fonts --keyboard-layoutdir=/Layouts --no-quarantine"
        dirs = cat.cask_dirs(self.prefix, {"HOME": "/Users/alice", "HOMEBREW_CASK_OPTS": opts})
        self.assertEqual(dirs["appdir"], "/Users/alice/Apps")
        self.assertEqual(dirs["fontdir"], "/Users/alice/Library/Fonts")    # brew reads a word only with its "="
        self.assertEqual(dirs["keyboard_layoutdir"], "/Layouts")
        self.assertEqual(dirs["qlplugindir"], "/Users/alice/Library/QuickLook")
        line = locate.EnvLine(path="/etc/homebrew/brew.env", lineno=1, name="HOMEBREW_CASK_OPTS",
                              value="--appdir=/Shared/Apps")
        self.assertEqual(cat.cask_dirs(self.prefix, {"HOME": "/Users/alice"}, [line])["appdir"], "/Shared/Apps")
        config = {"default": {"appdir": "/Applications"}, "env": {"appdir": "/Env"}, "explicit": {"fontdir": "/F"}}
        merged = cat.dirs_from_config(config, dirs)
        self.assertEqual((merged["appdir"], merged["fontdir"]), ("/Env", "/F"))


class ArtifactRuleTest(TempDirTest):
    """The cask artifact rules: the shapes normalised, the privileged flags, the targets and the version key"""

    def setUp(self):
        super().setUp()
        for name, directory in (("LAUNCH_DAEMONS", "LaunchDaemons"), ("LAUNCH_AGENTS", "LaunchAgents")):
            patcher = mock.patch.object(cat, name, self.path(directory))
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_system_launch_agent_needs_the_root_pass(self):
        agents = self.path("LaunchAgents")
        os.makedirs(agents)
        raw = [[":uninstall", {":launchctl": "com.x.updater"}]]
        self.assertEqual(self.flags(raw), (False, False))
        write(os.path.join(agents, "com.x.updater.plist"), "<plist/>")
        self.assertEqual(self.flags(raw), (False, True))

    def test_flight_steps_rerun_at_uninstall_with_sudo(self):
        step = {":type": "symlink", ":uninstall": True, ":sudo": "if_needed",
                ":source": {":path": "{{appdir}}/X.app/bin/x"}}
        self.assertEqual(self.flags([[":postflight_steps", {":steps": [step]}]]), (True, True))
        no_sudo = dict(step, **{":sudo": False})
        self.assertEqual(self.flags([[":postflight_steps", {":steps": [no_sudo]}]]), (True, False))
        install_only = {k: v for k, v in step.items() if k != ":uninstall"}
        self.assertEqual(self.flags([[":preflight_steps", {":steps": [install_only]}]]), (True, False))
        self.assertEqual(self.flags([[":postflight_steps", {}]]), (True, True))

    def ctx(self, **kw):
        """Return a privilege context whose app directory and prefix `bin` exist and the user can write

        @param kw  fields that replace the defaults, such as `system_loaded`
        @returns   the context
        """
        apps = self.path("Applications")
        os.makedirs(apps, exist_ok=True)
        defaults: dict[str, Any] = {"prefix": self.path("prefix"), "home": self.path("home"), "uid": os.geteuid(),
                                    "dirs": {"appdir": apps, "fontdir": self.path("Fonts")}}
        defaults.update(kw)
        os.makedirs(os.path.join(defaults["prefix"], "bin"), exist_ok=True)
        return cat.PrivilegeContext(**defaults)

    def flags(self, raw, ctx=None):
        """Return the privileged flags of a cask with the artifacts given

        @param raw  the artifacts, in any shape Homebrew writes them in
        @param ctx  the privilege context; None takes the default one
        @returns    `(privileged_install, privileged_uninstall)`
        """
        return cat.privileged_flags(cat.normalise_artifacts(raw), ctx or self.ctx())

    def test_both_shapes_normalise_alike(self):
        raw = cat.normalise_artifacts([[":binary", ["$APPDIR/X.app/bin/x"], {":target": "/usr/local/bin/x"}],
                                       [":uninstall", {":pkgutil": "com.x", ":quit": "com.x"}]])
        installed = cat.normalise_artifacts([{"binary": ["/Applications/X.app/bin/x", {"target": "/usr/local/bin/x"}],
                                              "target": "/usr/local/bin/x"},
                                             {"uninstall": [{"pkgutil": "com.x", "quit": "com.x"}]}])
        self.assertEqual([a.kind for a in raw], [a.kind for a in installed])
        self.assertEqual(raw[0].options, {"target": "/usr/local/bin/x"})
        self.assertEqual(installed[0].target, "/usr/local/bin/x")
        self.assertEqual(raw[1].directives, installed[1].directives)
        summary = cat.normalise_artifacts([{"postflight, uninstall_postflight": None}])
        self.assertEqual([a.kind for a in summary], ["postflight", "uninstall_postflight"])

    def test_install_rules(self):
        cases = [
            ([[":pkg", ["Install.pkg"]]], (True, False)),
            ([{"pkg": ["Install.pkg", {"allow_untrusted": True}]}], (True, False)),
            ([[":installer", {":script": {":executable": "install.sh", ":sudo": True}}]], (True, False)),
            ([[":installer", {":script": {":executable": "install.sh", ":args": ["-b"]}}]], (False, False)),
            ([{"installer": [{"manual": "Install Foo.app"}]}], (False, False)),
            ([[":preflight_steps", {":steps": []}]], (True, False)),
            ([{"postflight": None}], (True, False)),
            ([[":keyboard_layout", ["Layout.bundle"]]], (True, True)),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(self.flags(raw), expected)

    def test_uninstall_rules(self):
        cases = [
            ([[":uninstall", {":pkgutil": "com.x"}]], (False, True)),
            ([[":uninstall", {":kext": "com.x.kext"}]], (False, True)),
            ([[":uninstall", {":delete": "/Library/X"}]], (False, True)),
            ([[":uninstall", {":rmdir": "~/.x"}]], (False, True)),
            ([[":uninstall", {":script": {":executable": "rm.sh", ":sudo": True}}]], (False, True)),
            ([{"uninstall": [{"early_script": {"executable": "pre.sh", "sudo": True}}]}], (False, True)),
            ([[":uninstall", {":script": {":executable": "rm.sh"}}]], (False, False)),
            ([[":uninstall", {":quit": "com.x", ":signal": [["TERM", "com.x"]], ":login_item": "X",
                              ":trash": "~/x"}]], (False, False)),
            ([[":uninstall", {":launchctl": "com.x.agent"}]], (False, False)),
            ([[":uninstall_preflight_steps", {":steps": []}]], (False, True)),
            ([{"uninstall_postflight": None}], (False, True)),
            ([[":zap", {":delete": "/Library/X", ":pkgutil": "com.x"}]], (False, False)),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(self.flags(raw), expected)

    def test_target_in_a_directory_the_user_cannot_write(self):
        locked = self.path("locked")
        os.makedirs(locked)
        os.chmod(locked, 0o555)
        self.addCleanup(os.chmod, locked, 0o755)
        if os.access(locked, os.W_OK):
            self.skipTest("running as root")
        raw = [[":artifact", ["demos"], {":target": os.path.join(locked, "demos")}]]
        self.assertEqual(self.flags(raw), (True, True))
        missing = [[":artifact", ["demos"], {":target": self.path("no", "such", "dir", "demos")}]]
        self.assertEqual(self.flags(missing), (True, True))
        self.assertEqual(self.flags([[":app", ["Foo.app"]]]), (False, False))

    def test_target_tree_with_a_foreign_entry(self):
        ctx = self.ctx()
        app = os.path.join(ctx.dirs["appdir"], "Foo.app")
        helper = write(os.path.join(app, "Contents", "Library", "helper"), "x")
        self.assertEqual(self.flags([[":app", ["Foo.app"]]], ctx), (False, False))
        with mock.patch.object(cat.os, "lstat", side_effect=root_owned_lstat(helper)):
            self.assertFalse(cat.tree_owned_by(app, ctx.uid))
            self.assertEqual(self.flags([[":app", ["Foo.app"]]], ctx), (False, True))
            self.assertEqual(self.flags([{"app": ["Foo.app"], "target": app}], ctx), (False, True))

    def test_unreadable_directory_counts_as_not_owned(self):
        locked = self.path("Applications", "Locked.app", "Contents")
        os.makedirs(locked)
        os.chmod(locked, 0o000)
        self.addCleanup(os.chmod, locked, 0o755)
        if os.access(locked, os.R_OK):
            self.skipTest("running as root")
        self.assertFalse(cat.tree_owned_by(self.path("Applications", "Locked.app"), os.geteuid()))

    def test_launchctl_label_of_the_system_domain(self):
        daemons = self.path("LaunchDaemons")
        os.makedirs(daemons)
        raw = [[":uninstall", {":launchctl": ["com.x.helper", "com.x.agent"]}]]
        with mock.patch.object(cat, "LAUNCH_DAEMONS", daemons):
            self.assertEqual(self.flags(raw), (False, False))
            loaded = self.ctx(system_loaded=lambda label: label == "com.x.agent")
            self.assertEqual(self.flags(raw, loaded), (False, True))
            write(os.path.join(daemons, "com.x.helper.plist"), "<plist/>")
            self.assertEqual(self.flags(raw), (False, True))
            wildcard = [[":uninstall", {":launchctl": "com.x.*"}]]
            self.assertEqual(self.flags(wildcard), (False, True))

    def test_artifact_targets(self):
        ctx = self.ctx()

        def targets(raw):
            return [t for a in cat.normalise_artifacts(raw)
                    for t in cat.artifact_targets(a, ctx.dirs, ctx.prefix, ctx.home)]
        apps = ctx.dirs["appdir"]
        self.assertEqual(targets([[":app", ["Docker.app"]]]), [os.path.join(apps, "Docker.app")])
        self.assertEqual(targets([[":app", ["Foo.app"], {":target": "Bar.app"}]]), [os.path.join(apps, "Bar.app")])
        self.assertEqual(targets([[":suite", ["KiCad"]]]), [os.path.join(apps, "KiCad")])
        self.assertEqual(targets([[":binary", ["$APPDIR/Docker.app/Contents/Resources/bin/docker"]]]),
                         [os.path.join(ctx.prefix, "bin", "docker")])
        self.assertEqual(targets([[":binary", ["$HOMEBREW_PREFIX/Caskroom/x/base/bin/conda"]]]),
                         [os.path.join(ctx.prefix, "bin", "conda")])
        self.assertEqual(targets([[":binary", ["x"], {":target": "~/bin/x"}]]), [os.path.join(ctx.home, "bin", "x")])
        self.assertEqual(targets([[":manpage", ["$APPDIR/X.app/x.8"]]]),
                         [os.path.join(ctx.prefix, "share", "man", "man8", "x.8")])
        self.assertEqual(targets([[":font", ["Inter.ttc"]]]), [self.path("Fonts", "Inter.ttc")])
        self.assertEqual(targets([[":artifact", ["demos"], {":target": "relative/demos"}]]), [])
        self.assertEqual(targets([[":pkg", ["x.pkg"]]]), [])

    def test_version_key(self):
        versions = ["1.10", "1.8.2_1", "1.8.2", "1.0.1", "1.0", "2.0_10", "2.0_9"]
        self.assertEqual(sorted(versions, key=cat.version_key),
                         ["1.0", "1.0.1", "1.8.2", "1.8.2_1", "1.10", "2.0_9", "2.0_10"])
        self.assertLess(cat.version_key("4.43.2,199162"), cat.version_key("4.44.0,200000"))


if __name__ == "__main__":
    unittest.main()

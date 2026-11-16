"""Shared fixtures of the Homebrew tests

The trimmed API payload, and a temporary Homebrew prefix with a Cellar, a Caskroom, links, pins, taps and
`brew.env` files.
"""

import datetime
import json
import os
import re
import shutil
import unittest
from typing import Any

from brew_ports import model, runner as r, system
from brew_ports.homebrew import catalogue as cat
from tests.unit.helpers import TempDirTest, make_instance, write_file as write
from tests.unit.test_runner import QuietConsole

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "homebrew")
API = os.path.join(FIXTURES, "api")
API_FILE = os.path.join(API, "internal", "packages.arm64_tahoe.jws.json")
TODAY = datetime.date(2026, 11, 12)
STAMP = "20260101000000.000"


def fixture_text(*parts):
    """Return the text of a fixture under `fixtures/homebrew`

    @param parts  the fixture's path components
    @returns      the text
    """
    with open(os.path.join(FIXTURES, *parts), encoding="utf-8") as fh:
        return fh.read()


def receipt(name, **changes):
    """Return a fixture receipt of `fixtures/homebrew/receipts`, some keys replaced

    @param name     the receipt's file name, without `.json`
    @param changes  the keys to replace, with their values
    @returns        the decoded receipt
    """
    data = json.loads(fixture_text("receipts", name + ".json"))
    data.update(changes)
    return data


def payload():
    """Return the decoded payload of the fixture API file

    @returns  the payload
    """
    return cat.read_payload(API_FILE)


def install_api(cache_dir, tag="arm64_tahoe"):
    """Copy the fixture API files into `<cache_dir>/api/` under the given tag

    @param cache_dir  the instance's download cache
    @param tag        the bottle tag of the per-arch API file
    @returns          the per-arch API file's path
    """
    api = os.path.join(cache_dir, "api")
    os.makedirs(os.path.join(api, "internal"), exist_ok=True)
    for name in ("formula_names.txt", "formula_aliases.txt", "cask_names.txt"):
        shutil.copy(os.path.join(API, name), os.path.join(api, name))
    shutil.copy(os.path.join(API, "internal", "executables.txt"), os.path.join(api, "internal", "executables.txt"))
    target = os.path.join(api, "internal", f"packages.{tag}.jws.json")
    shutil.copy(API_FILE, target)
    return target


def fixture_catalogue(prefix="/opt/homebrew", appdir=None, home="/Users/alice", today=TODAY):
    """Return the catalogue of the fixture payload and name files

    @param prefix  the instance's prefix
    @param appdir  the cask app directory; None keeps `/Applications`
    @param home    the user's home directory
    @param today   the date deprecations and disables are judged on
    @returns       the catalogue
    """
    dirs = cat.cask_dirs(prefix, {"HOME": home})
    if appdir:
        dirs["appdir"] = appdir
    return cat.Catalogue.from_payload(payload(), api_dir=API, prefix=prefix, dirs=dirs, home=home, today=today)


def write_json(path, data):
    """Write a value as indented JSON, making the file's directory first

    @param path  the file
    @param data  the value
    @returns     the path
    """
    return write(path, json.dumps(data, indent=1))


def symlink(path, target):
    """Make a symlink, making its directory first

    @param path    the link
    @param target  the link's text
    @returns       the link's path
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.symlink(target, path)
    return path


def root_owned_lstat(path):
    """Return an `os.lstat` stand-in that reports `path` as owned by root

    @param path  the path to report, compared by its text
    @returns     the stand-in, which passes every other path to the real `os.lstat`
    """
    real_lstat = os.lstat

    def lstat(target, *args, **kw):
        st = real_lstat(target, *args, **kw)
        if os.fspath(target) != path:
            return st
        fields = list(st[:10])
        fields[4] = 0
        return os.stat_result(fields)
    return lstat


def make_keg(prefix, name, version, receipt_data=None, *, bins=(), sbins=(), plists=()):
    """Make a keg in the prefix's Cellar, with its receipt, executables and plists

    @param prefix        the Homebrew prefix
    @param name          the formula
    @param version       the keg's version
    @param receipt_data  the content of `INSTALL_RECEIPT.json`; None for a keg without a receipt
    @param bins          the executables in `bin`
    @param sbins         the executables in `sbin`
    @param plists        the plists at the top of the keg
    @returns             the keg
    """
    keg = os.path.join(prefix, "Cellar", name, version)
    os.makedirs(keg)
    if receipt_data is not None:
        write_json(os.path.join(keg, "INSTALL_RECEIPT.json"), receipt_data)
    for exe in bins:
        write(os.path.join(keg, "bin", exe), "#!/bin/sh\n", 0o755)
    for exe in sbins:
        write(os.path.join(keg, "sbin", exe), "#!/bin/sh\n", 0o755)
    for plist in plists:
        write(os.path.join(keg, plist), "<plist/>\n")
    return keg


def make_cask(prefix, token, version, receipt_data=None, config=None, *, data=(), metadata=True):
    """Make a cask's Caskroom entry with its version directory and metadata

    @param prefix        the Homebrew prefix
    @param token         the cask
    @param version       the installed version
    @param receipt_data  the content of `.metadata/INSTALL_RECEIPT.json`; None writes none
    @param config        the content of `.metadata/config.json`; None writes none
    @param data          further directories of the Caskroom entry
    @param metadata      write the version's cask JSON under `.metadata`
    @returns             the Caskroom entry
    """
    room = os.path.join(prefix, "Caskroom", token)
    os.makedirs(os.path.join(room, version))
    if metadata:
        write(os.path.join(room, ".metadata", version, STAMP, "Casks", token + ".json"), "{}")
    if receipt_data is not None:
        write_json(os.path.join(room, ".metadata", "INSTALL_RECEIPT.json"), receipt_data)
    if config is not None:
        write_json(os.path.join(room, ".metadata", "config.json"), config)
    for entry in data:
        os.makedirs(os.path.join(room, entry))
    return room


class HomebrewTree:
    """The scenario prefix of the inventory tests, every path under a temporary root"""

    def __init__(self, root):
        """Name the tree's paths under a root; `build` makes them

        @param root  the temporary root
        """
        self.root = root
        self.prefix = os.path.join(root, "opt", "homebrew")
        self.appdir = os.path.join(root, "Applications")
        self.home = os.path.join(root, "Users", "alice")
        self.cache = os.path.join(self.home, "Library", "Caches", "Homebrew")

    def environ(self, **extra):
        """Return the tree's environment, whose `HOMEBREW_CASK_OPTS` names the tree's app directory

        @param extra  further variables, which replace the defaults
        @returns      the environment
        """
        env = {"HOME": self.home, "PATH": "/usr/bin:/bin", "HOMEBREW_CASK_OPTS": "--appdir=" + self.appdir}
        env.update(extra)
        return env

    def instance(self, **kw):
        """Return the tree's Homebrew instance

        @param kw  further `Instance` fields, which replace the defaults
        @returns   the instance
        """
        defaults: dict[str, Any] = {"identity": system.identity(self.prefix), "repository": self.prefix,
                                    "cache_dir": self.cache}
        defaults.update(kw)
        return make_instance(prefix=self.prefix, **defaults)

    def info_json(self):
        """Return the fixture `brew info --json=v2 --installed` output, the tree's paths filled in

        @returns  the JSON text
        """
        return fixture_text("info-installed.json").replace("@PREFIX@", self.prefix).replace("@APPDIR@", self.appdir)

    def build(self):
        """Make the tree: kegs, links, pins, casks, taps and `brew.env` files

        @returns  the tree itself
        """
        p = self.prefix
        os.makedirs(os.path.join(p, "Library", "Homebrew"))
        write(os.path.join(p, "bin", "brew"), "#!/bin/sh\n", 0o755)
        os.makedirs(self.appdir)
        bottle = receipt("formula-bottle")
        make_keg(p, "jq", "1.8.2", bottle, bins=["jq"])
        make_keg(p, "oniguruma", "6.9.10", dict(bottle, installed_on_request=False, runtime_dependencies=[]))
        make_keg(p, "wget", "1.24.5", None, bins=["wget"])
        make_keg(p, "wget", "1.25.0_2", dict(bottle, runtime_dependencies=[]), bins=["wget", "wget2"])
        make_keg(p, "postgresql@16", "16.10", dict(bottle, runtime_dependencies=[]), bins=["psql", "postgres"],
                 plists=["homebrew.mxcl.postgresql@16.plist"])
        make_keg(p, "act_runner", "0.2.11", dict(bottle, runtime_dependencies=[]), bins=["act_runner"])
        make_keg(p, "libfido2", "1.16.0", dict(bottle, installed_on_request=False, runtime_dependencies=[]))
        make_keg(p, "cython", "3.0.0", receipt("formula-old-source-build"), bins=["cython"], sbins=["cythonize"])
        make_keg(p, "dbus", "1.16.2", None, bins=["dbus-daemon"])
        make_keg(p, "alloy-analyzer", "1.0", dict(bottle, runtime_dependencies=[]))
        symlink(os.path.join(p, "Cellar", "alloy"), "alloy-analyzer")
        symlink(os.path.join(p, "opt", "jq"), "../Cellar/jq/1.8.2")
        symlink(os.path.join(p, "opt", "wget"), "../Cellar/wget/1.25.0_2")
        symlink(os.path.join(p, "opt", "postgresql@16"), "../Cellar/postgresql@16/16.10")
        symlink(os.path.join(p, "opt", "gone"), "../Cellar/gone/1.0")
        for name, version in (("jq", "1.8.2"), ("oniguruma", "6.9.10"), ("wget", "1.25.0_2"),
                              ("alloy-analyzer", "1.0")):
            symlink(os.path.join(p, "var", "homebrew", "linked", name), f"../../../Cellar/{name}/{version}")
        symlink(os.path.join(p, "var", "homebrew", "pinned", "wget"), "../../../Cellar/wget/1.25.0_2")

        config = {"default": {"appdir": self.appdir}, "env": {}, "explicit": {}}
        make_cask(p, "docker-desktop", "4.43.2,199162", receipt("cask-docker-desktop"), config)
        symlink(os.path.join(p, "Caskroom", "docker"), "docker-desktop")
        make_cask(p, "appcleaner", "3.7", receipt("cask-depends-on-cask", runtime_dependencies={},
                                                  uninstall_artifacts=[]), config)
        make_cask(p, "0-ad", "0.28.0", None, config)
        make_cask(p, "aptible", "1.0.7", None, config)
        make_cask(p, "sshfs-helper", "2.0", receipt("cask-depends-on-cask"), config)
        make_cask(p, "macfuse-like", "1.2.7", None, config)
        make_cask(p, "miniconda", "py314_26.9.4-0", None, config, data=["base"])
        make_cask(p, "mist", "1.0", None, config)
        make_cask(p, "leftover", "1.0", None, None, metadata=False)

        os.makedirs(os.path.join(p, "Library", "Taps", "homebrew", "homebrew-core", ".git"))
        os.makedirs(os.path.join(p, "Library", "Taps", "alice", "homebrew-casks", ".git"))
        os.makedirs(os.path.join(p, "Library", "Taps", "alice", "homebrew-local", "Formula"))

        write(os.path.join(p, "etc", "homebrew", "brew.env"),
              "# managed by alice\n"
              "HOMEBREW_NO_ANALYTICS=1\n"
              "  HOMEBREW_NO_AUTOREMOVE=\n"
              "HOMEBREW_PREFIX=/elsewhere\n"
              "https_proxy=http://proxy.example:3128\n"
              "HTTPS_PROXY=http://ignored.example\n"
              "HOMEBREW_NO_SUDO=1\n"
              "HOMEBREW_NO_COLOR\n")
        write(os.path.join(self.home, ".homebrew", "brew.env"), "HOMEBREW_DEVELOPER=1\nHOMEBREW_DEBUG=1")
        return self


def fake(tmp, responses=None, environ=None, host_arch="arm64", default=None):
    """Return a FakeRunner whose argv keys spell the temporary root as `<tmp>`

    `launchctl print` answers "not found" unless a response names it.

    @param tmp        the temporary root
    @param responses  the canned responses by argv
    @param environ    the environment; None for `HOME` alone, set to `tmp`
    @param host_arch  the host's architecture
    @param default    the response, or a function of the argv that gives one, for an argv not listed
    @returns          the runner
    """
    def fallback(key):
        if default is not None:
            return default(key) if callable(default) else default
        if key[:2] == ("/bin/launchctl", "print"):
            return r.FakeResponse(exit=113, stderr="Could not find service\n")
        return None
    return r.FakeRunner(responses=responses or {}, default=fallback, placeholders={tmp: "<tmp>"},
                        console=QuietConsole(), environ=environ or {"HOME": tmp}, host_arch=host_arch,
                        out_dir=os.path.join(tmp, "out"))


class FixturePayloadTest(unittest.TestCase):
    """The fixture API payload, and the made-up user that its paths name"""

    def test_fixture_payload_is_a_json_string(self):
        with open(API_FILE, encoding="utf-8") as fh:
            outer = json.load(fh)
        self.assertIsInstance(outer["payload"], str)
        data = payload()
        for key in ("formulae", "casks", "formula_aliases", "formula_renames", "formula_tap_migrations",
                    "cask_renames", "cask_tap_migrations"):
            self.assertIn(key, data)
        self.assertIn("wget", data["formulae"])
        self.assertIn(":pkg", [a[0] for a in data["casks"]["aptible"]["raw_artifacts"]])

    def test_fixture_home_directories_are_the_made_up_user(self):
        for dirpath, _, filenames in os.walk(FIXTURES):
            for name in filenames:
                with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                    text = fh.read()
                for match in re.finditer(r"/Users/([^/\"\s]+)", text):
                    self.assertIn(match.group(1), ("alice", "Shared"), name)


class TreeTest(TempDirTest):
    """The scenario tree, with its rename link, its `brew info` JSON and its instance"""

    def test_tree_builds(self):
        tree = HomebrewTree(self.tmp).build()
        self.assertTrue(os.path.islink(os.path.join(tree.prefix, "Cellar", "alloy")))
        self.assertIn(tree.prefix, tree.info_json())
        self.assertIsInstance(tree.instance(), model.Instance)


if __name__ == "__main__":
    unittest.main()

"""Shared builders of the Homebrew health tests

A temporary prefix with kegs and casks, a synthetic inventory and catalogue, a scan bundle and a FakeRunner that
answers `brew doctor` and `git status`.
"""

import datetime
import json
import os
from typing import Any
from unittest import mock

from brew_ports import doctor_report, model, runner as r, scan, system
from brew_ports.homebrew import health, inventory
from brew_ports.homebrew.catalogue import Catalogue
from tests.unit.helpers import TempDirTest, make_instance, make_package
from tests.unit.test_homebrew_support import symlink, write
from tests.unit.test_runner import QuietConsole

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "homebrew_health")
ARCH = ("/usr/bin/arch", "-arm64")
GIT_STATUS = (health.GIT, "--no-optional-locks", "-c", "core.fsmonitor=false", "-C")
NOW = 1800000000.0
TODAY = datetime.date(2026, 11, 13)
STAMP = "20260101000000.000"


def fixture(name, **tokens):
    """Return a fixture of `fixtures/homebrew_health` with its `@TOKEN@` placeholders filled in

    @param name    the fixture's file name
    @param tokens  the text of each placeholder, by its name
    @returns       the text
    """
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        text = fh.read()
    for key, value in tokens.items():
        text = text.replace(f"@{key}@", value)
    return text


def service(label, plist, prefix, package, **kw):
    """Build an owned, unloaded user service of a formula

    @param label    the launchd label
    @param plist    the plist's path
    @param prefix   the prefix whose program the plist runs
    @param package  the owning formula
    @param kw       further `Service` fields, such as `loaded` or `domain`
    @returns        the service
    """
    defaults: dict[str, Any] = {"scope": "user", "domain": None, "loaded": False, "running": False, "pid": None,
                                "exit_timeout_s": 20, "owned": True, "data_dirs": [], "package_kind": "formula",
                                "program": None}
    defaults.update(kw)
    return model.Service(label=label, plist=plist, instance_prefix=prefix, package=package, **defaults)


def path_entry(path):
    """Return the scan record of an existing PATH entry that names no instance

    @param path  the directory
    @returns     the record
    """
    return {"text": path, "path": path, "instance_prefix": None, "exists": True, "usr_local": False}


class HealthCase(TempDirTest):
    """A Homebrew instance at `<tmp>/opt/homebrew` for the detectors to judge

    Each test fills in its inventory, catalogue, services, linkage report and environment.
    """

    def setUp(self):
        super().setUp()
        self.prefix = self.path("opt", "homebrew")
        self.home = self.path("Users", "alice")
        self.appdir = self.path("Applications")
        for directory in (os.path.join(self.prefix, "Library", "Homebrew"), os.path.join(self.prefix, "Cellar"),
                          os.path.join(self.prefix, "bin"), self.home, self.appdir):
            os.makedirs(directory, exist_ok=True)
        cache_dir = os.path.join(self.home, "Library", "Caches", "Homebrew")
        self.inst = make_instance(prefix=self.prefix, identity=system.identity(self.prefix), repository=self.prefix,
                                  cache_dir=cache_dir)
        self.inv = inventory.HomebrewInventory(instance_prefix=self.prefix, used_json=True)
        self.formulae = {}          # catalogue formula entries
        self.casks = {}             # catalogue cask entries
        api_file = os.path.join(cache_dir, "api", "internal", "packages.arm64_tahoe.jws.json")
        self.cat_kw: dict[str, Any] = {"source": "api", "api_mtime": NOW - 86400, "api_file": api_file}
        self.no_catalogue = False
        self.services = []
        self.linkage = {}
        self.environment = {}
        self.responses = {}
        self.doctor = r.FakeResponse()          # brew doctor finds nothing
        self.host_arch = "arm64"
        self.run_dir = None
        self.extra = []                          # more (instance, catalogue, inventory) entries
        self.fake = r.FakeRunner(console=QuietConsole(), environ={})   # replaced by the runner of each detect()
        self.issues: list[model.Issue] = []                               # the findings of the last detect()

    # Building the prefix ------------------------------------------------------------

    def keg(self, rack, version, receipt=True, requested=True):
        """Make a keg directory under the Cellar, with a receipt or recorded as receipt-less

        @param rack       the formula's Cellar directory
        @param version    the keg's version
        @param receipt    write an `INSTALL_RECEIPT.json`
        @param requested  the receipt's `installed_on_request`
        @returns          the keg's path
        """
        keg = os.path.join(self.prefix, "Cellar", rack, version)
        os.makedirs(keg)
        if receipt:
            write(os.path.join(keg, inventory.RECEIPT),
                  json.dumps({"installed_on_request": requested, "source": {"tap": "homebrew/core"}}))
        else:
            self.inv.receiptless_kegs.append(keg)
        return keg

    def formula(self, name, *, versions=("1.0",), receipt=True, known=True, linked=True, opt=True, rack=None, **kw):
        """Add a formula package with its kegs, linked and with an `opt` link to the newest keg unless told otherwise

        @param name      the formula
        @param versions  the versions of its kegs, the newest last
        @param receipt   give each keg a receipt
        @param known     put the formula in the catalogue
        @param linked    link the newest keg
        @param opt       give the newest keg an `opt` link
        @param rack      the Cellar directory; None for the name
        @param kw        further fields of the package
        @returns         the package
        """
        rack = rack or name
        kegs = [self.keg(rack, v, receipt=receipt) for v in versions]
        self.inv.kegs[name] = kegs
        if linked:
            symlink(os.path.join(self.prefix, "var", "homebrew", "linked", rack), kegs[-1])
        if opt:
            symlink(os.path.join(self.prefix, "opt", name), kegs[-1])
        if known:
            self.formulae.setdefault(name, {})
        kw.setdefault("receipt_ok", receipt)
        kw.setdefault("requested", True if receipt else None)
        pkg = make_package(name, prefix=self.prefix, version=versions[-1], linked=linked, **kw)
        self.inv.packages.append(pkg)
        return pkg

    def cask(self, token, *, version="1.0", apps=("Foo.app",), caskfile=True, known=True, receipt=True, **kw):
        """Add a cask package with its Caskroom directory, its receipt and a `config.json`

        The receipt lists the apps, and the `config.json` names the test's app directory.

        @param token     the cask
        @param version   the installed version
        @param apps      the apps the receipt lists
        @param caskfile  write the version's cask JSON under `.metadata`
        @param known     put the cask in the catalogue
        @param receipt   write the receipt
        @param kw        further fields of the package
        @returns         the Caskroom directory
        """
        room = os.path.join(self.prefix, "Caskroom", token)
        os.makedirs(os.path.join(room, version))
        stamp = os.path.join(room, ".metadata", version, STAMP, "Casks")
        os.makedirs(stamp)
        if caskfile:
            write(os.path.join(stamp, token + ".json"), "{}")
        if receipt:
            write(os.path.join(room, ".metadata", inventory.RECEIPT),
                  json.dumps({"installed_on_request": True, "uninstall_artifacts": [{"app": [a]} for a in apps]}))
        write(os.path.join(room, ".metadata", "config.json"), json.dumps({"explicit": {"appdir": self.appdir}}))
        if known:
            self.casks.setdefault(token, {})
        pkg = make_package(token, kind="cask", prefix=self.prefix, version=version, linked=None, **kw)
        self.inv.packages.append(pkg)
        return room

    # Running the detectors ----------------------------------------------------------

    def catalogue(self):
        """Return the catalogue of `formulae`, `casks` and `cat_kw`, or None under `no_catalogue`

        @returns  the catalogue, or None
        """
        if self.no_catalogue:
            return None
        return Catalogue(formulae=self.formulae, casks=self.casks, prefix=self.prefix, home=self.home, today=TODAY,
                         **self.cat_kw)

    def runner(self):
        """Return a FakeRunner over `responses` that answers `brew doctor` with `doctor`, `git status` with no changes

        @returns  the runner
        """
        def respond(key):
            if "doctor" in key:
                return self.doctor
            if key[:len(GIT_STATUS)] == GIT_STATUS:
                return r.FakeResponse()
            return None
        return r.FakeRunner(responses=self.responses, default=respond, placeholders={self.tmp: "<tmp>"},
                            console=QuietConsole(), environ={"HOME": self.home, "PATH": "/usr/bin:/bin"},
                            host_arch=self.host_arch, out_dir=self.path("out"), run_dir=self.run_dir)

    def bundle(self):
        """Return the scan bundle of the instance, its catalogue and inventory, and the `extra` entries

        @returns  the bundle
        """
        entries = [(self.inst, self.catalogue(), self.inv)] + list(self.extra)
        result = model.ScanResult(created="2026-11-13T10:00:00+1100", system={"host_arch": self.host_arch},
                                  instances=[e[0] for e in entries],
                                  packages=[p for e in entries for p in e[2].packages], services=self.services,
                                  environment=self.environment, linkage=self.linkage, interpreter_extras={})
        return scan.ScanBundle(result=result, brew=entries)

    def detect(self, bundle=None):
        """Run every Homebrew detector at a constant time, keeping the runner and the findings

        @param bundle  the scan bundle; None builds the test's own
        @returns       the findings
        """
        self.fake = self.runner()
        with mock.patch.object(health, "_now", return_value=NOW):
            self.issues = health.detect(bundle or self.bundle(), self.fake)
        return self.issues

    def found(self, code, issues=None):
        """Return the findings of one code

        @param code    the finding's code
        @param issues  the findings to search; None for those of the last `detect`
        @returns       the findings of that code, in their order
        """
        return [i for i in (self.issues if issues is None else issues) if i.code == code]

    def only(self, code):
        """Return the single finding of `code` that `detect` returns, failing the test on any other count

        @param code  the finding's code
        @returns     the finding
        """
        found = self.found(code, self.detect())
        self.assertEqual(len(found), 1, [(i.code, i.subject, i.title) for i in found])
        return found[0]

    @staticmethod
    def fixes(issue):
        """Return what the report tells the user to do about a finding

        @param issue  the finding
        @returns      the lines the report prints under it
        """
        return doctor_report.fix_lines(issue)

    def brew_argv(self, *args):
        """Return the argv of the instance's `brew` under `arch -arm64`

        @param args  the arguments after the binary
        @returns     the argv
        """
        return list(ARCH) + [self.inst.binary] + list(args)

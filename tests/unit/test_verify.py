"""The verify checks, the phase 4 gate and `brew-ports verify`"""

import argparse
import json
import os
import unittest
from unittest import mock

from brew_ports import runner as r, snapshot, state, verify
from brew_ports.context import Context
from brew_ports.homebrew.catalogue import Catalogue
from brew_ports.homebrew.inventory import HomebrewInventory
from brew_ports.model import Action, Manager, OnFailure, Phase, Usability
from tests.unit.fixtures.doctor import builders as db
from tests.unit.fixtures.envclean import builders as eb
from tests.unit.fixtures.macports import builders as mb
from tests.unit.fixtures.verify import builders as vb
from tests.unit.helpers import TempDirTest, make_package


class VerifyTest(TempDirTest):
    """A Homebrew target in /opt/homebrew, MacPorts in /opt/local and Homebrew in /usr/local, and their probes"""

    fake: vb.RecordingRunner        # the runner of the last check

    def setUp(self):
        super().setUp()
        self.home = self.path("Users", "alice")
        self.apps = self.path("Applications")
        os.makedirs(os.path.join(self.home, ".local", "bin"))
        os.makedirs(self.apps)
        self.brew = eb.instance(self.tmp, Manager.BREW, "opt/homebrew")
        self.ports = eb.instance(self.tmp, Manager.PORTS, "opt/local")
        self.ul = eb.instance(self.tmp, Manager.BREW, "usr/local", roots=eb.USR_LOCAL_ROOTS)
        self.host = vb.Host()
        self.sd = self.state_dir()
        self.run_dir = self.sd.new_run()

    def runner(self, console=None):
        """Return a runner of phase 8 that the test's host answers, with the test's home and appdir

        @param console  the console; None for a quiet one
        @returns        the runner, which keeps the actions it ran
        """
        fake = vb.RecordingRunner(default=self.host, console=console or eb.QuietConsole(), run_dir=self.run_dir,
                                  environ={"HOME": self.home, "HOMEBREW_CASK_OPTS": f"--appdir={self.apps}"})
        fake.phase = 8
        return fake

    def plan(self, instances=None, target=None, **kw):
        """Return a plan into the Homebrew target, or another

        @param instances  the plan's instances; None for the three of the test
        @param target     the target; None for /opt/homebrew
        @param kw         `Plan` fields, such as `mappings`
        @returns          the plan
        """
        return eb.plan(target or self.brew, instances or [self.brew, self.ports, self.ul], **kw)

    def bundle(self, instances=None, packages=(), **kw):
        """Return a scan of the host

        @param instances  the instances it finds; None for the three of the test
        @param packages   the packages it finds
        @param kw         the scan's login shell, GUI PATH or live PATH
        @returns          the scan bundle
        """
        return eb.bundle(instances or [self.brew, self.ports, self.ul], packages, **kw)

    def check(self, plan, gate=False, bundle=None):
        """Run the checks of a plan with a new runner, kept in `fake`

        @param plan    the plan
        @param gate    whether to run the phase 4 gate's checks
        @param bundle  the scan; None for one of the three instances, without packages
        @returns       the result
        """
        self.fake = self.runner()
        return verify.check(bundle or self.bundle(), plan, self.fake, gate=gate)

    @staticmethod
    def failures(result, step):
        """Return the texts of a check's failures

        @param result  the result
        @param step    the check
        @returns       the texts, in order
        """
        return [f.text for f in result.failures if f.step == step]

    @staticmethod
    def reports(result, step):
        """Return the report lines of a check

        @param result  the result
        @param step    the check
        @returns       `(subject, text)` of each line, in order
        """
        return [(f.subject, f.text) for f in result.reports if f.step == step]

    def port(self, name, **kw):
        """Return a requested, active port of /opt/local

        @param name  the port
        @param kw    `Package` fields that override the defaults
        @returns     the package
        """
        return make_package(name, kind="port", prefix=self.ports.prefix, **kw)


class InstalledTest(VerifyTest):
    """Replacements installed: formulae, companions, pipx packages, casks and adopted casks"""

    def test_installed_at_the_major_of_the_target_version(self):
        vb.keg(self.brew.prefix, "wget", "1.25.0", exes=["wget"])
        vb.keg(self.brew.prefix, "ruby", "3.4.7", exes=["ruby"])
        self.host.info = vb.info([vb.formula("wget", ["1.25.0"]), vb.formula("ruby", ["3.4.7_1"])])
        plan = self.plan(mappings=[
            vb.mapping(self.port("wget", executables=["wget"]), "formula", "wget", version="1.25.0"),
            vb.mapping(self.port("ruby40"), "formula", "ruby", version="4.0.1"),
            vb.mapping(self.port("jq"), "formula", "jq", version="1.7.1")])
        result = self.check(plan)
        self.assertEqual(self.failures(result, "installed"), ["installed at 3.4.7_1, not at major 4 of 4.0.1",
                                                              f"jq is not installed in {self.brew.prefix}"])
        self.assertEqual({f.step for f in result.failures}, {"installed"})
        self.assertEqual(result.exit_code, verify.EXIT_VERIFY)
        self.assertEqual(result.lines()[0], "verify: 2 failures")

    def test_every_target_present_passes(self):
        vb.keg(self.brew.prefix, "wget", "1.25.0_1", exes=["wget"])
        self.host.info = vb.info([vb.formula("wget", ["1.25.0_1"])])
        result = self.check(self.plan(mappings=[vb.mapping(self.port("wget"), "formula", "wget", version="1.25.0")]))
        self.assertEqual(result.failures, [])
        self.assertEqual(result.exit_code, verify.EXIT_OK)

    def test_companions_at_any_version_and_pipx_mappings(self):
        source = self.port("py313-black", executables=["black"])
        plan = self.plan(mappings=[vb.mapping(source, "pip", "black", companions=["pipx"])])
        vb.keg(self.brew.prefix, "pipx", "1.7.1", exes=["pipx"])
        self.host.info = vb.info([vb.formula("pipx", ["1.7.1"])])
        self.host.pipx = {"black": {"metadata": {"main_package": {"package": "black", "apps": ["black", "blackd"]}}}}
        with open(os.path.join(self.home, ".local", "bin", "black"), "w") as fh:
            fh.write("#!/bin/sh\n")
        result = self.check(plan)
        self.assertEqual(result.failures, [])
        self.assertEqual(self.reports(result, "commands"), [])
        self.host.pipx = {}
        self.host.info = vb.info([])
        result = self.check(plan)
        self.assertEqual(self.failures(result, "installed"), ["black is not installed by pipx",
                                                              f"the companion is not installed in {self.brew.prefix}"])
        self.host.pipx = None
        self.assertEqual(self.failures(self.check(plan), "installed")[0], "pipx list --json exited 1 without its JSON")
        [pipx] = [a for a in self.fake.actions if "list" in a.argv and a.argv[-1] == "--json"]
        self.assertEqual(pipx.argv, ["/usr/bin/arch", "-arm64", os.path.join(self.brew.prefix, "bin", "pipx"), "list",
                                     "--json"])
        self.assertEqual((pipx.read_only, pipx.on_failure, pipx.env_profile), (True, OnFailure.PROBE, "brew"))

    def test_cask_targets_by_caskroom_and_json(self):
        vb.caskroom(self.brew.prefix, "firefox", "134.0")
        vb.caskroom(self.brew.prefix, "zed", "0.160")
        self.host.info = vb.info(casks=[vb.cask("firefox", "134.0")])
        casks = [vb.mapping(make_package(t, kind="cask", prefix=self.ul.prefix), "cask", t)
                 for t in ("firefox", "zed", "tb")]
        result = self.check(self.plan(mappings=casks))
        self.assertEqual(self.failures(result, "installed"), [
            "zed is not listed by brew info --json=v2 --installed",
            f"no Caskroom directory {os.path.join(self.brew.prefix, 'Caskroom', 'tb')}"])

    def adopted(self, source_instance, **kw):
        """Return a plan that maps the cask iterm2 of a source into the target, which holds and adopts it

        @param source_instance  the source instance
        @param kw               further `Plan` fields
        @returns                the plan
        """
        source = make_package("iterm2", kind="cask", prefix=source_instance.prefix)
        vb.caskroom(self.brew.prefix, "iterm2")
        self.host.info = vb.info(casks=[vb.cask("iterm2")])
        return self.plan(instances=[self.brew, self.ports, source_instance],
                         mappings=[vb.mapping(source, "cask", "iterm2", adopt=True)], **kw)

    def test_an_adopted_cask_leaves_a_drivable_source(self):
        record = vb.caskroom(self.ul.prefix, "iterm2")
        plan = self.adopted(self.ul, removal_set={self.ul.prefix: [("cask-adopted", "iterm2")]})
        self.assertEqual(self.failures(self.check(plan), "installed"),
                         [f"the adopted cask is still recorded in {record}"])
        self.assertEqual(self.failures(self.check(plan, gate=True), "installed"), [])
        os.rename(record, record + ".gone")
        self.assertEqual(self.failures(self.check(plan), "installed"), [])

    def test_a_cask_adopted_under_the_target_token(self):
        record = vb.caskroom(self.ul.prefix, "docker")
        vb.caskroom(self.brew.prefix, "docker-desktop")
        self.host.info = vb.info(casks=[vb.cask("docker-desktop")])
        source = make_package("docker", kind="cask", prefix=self.ul.prefix)
        plan = self.plan(mappings=[vb.mapping(source, "cask", "docker-desktop", adopt=True)],
                         removal_set={self.ul.prefix: [("cask-adopted", "docker")]})
        self.assertEqual(self.failures(self.check(plan, gate=True), "installed"), [])
        result = self.check(plan)
        self.assertEqual((self.failures(result, "installed"), self.failures(result, "removed")),
                         ([f"the adopted cask is still recorded in {record}"],
                          [f"the cask-adopted is still installed in {self.ul.prefix}"]))
        os.rename(record, record + ".gone")
        result = self.check(plan)
        self.assertEqual((self.failures(result, "installed"), self.failures(result, "removed")), ([], []))

    def test_an_adopted_record_left_under_an_old_token(self):
        record = vb.caskroom(self.ul.prefix, "docker")
        vb.caskroom(self.brew.prefix, "docker-desktop")
        self.host.info = vb.info(casks=[vb.cask("docker-desktop")])
        source = make_package("docker-desktop", kind="cask", prefix=self.ul.prefix)
        plan = self.plan(mappings=[vb.mapping(source, "cask", "docker-desktop", adopt=True)],
                         removal_set={self.ul.prefix: [("cask-adopted", "docker-desktop")]})
        bundle = self.bundle()
        bundle.brew = [(self.ul, None, HomebrewInventory(instance_prefix=self.ul.prefix,
                                                         caskrooms={"docker-desktop": record}))]
        result = self.check(plan, bundle=bundle)
        self.assertEqual((self.failures(result, "installed"), self.failures(result, "removed")),
                         ([f"the adopted cask is still recorded in {record}"],
                          [f"the cask-adopted is still installed in {self.ul.prefix}"]))

    def test_an_undrivable_sources_cask_record_stays(self):
        intel = eb.instance(self.tmp, Manager.BREW, "usr/local-intel", roots=eb.USR_LOCAL_ROOTS, drivable=False,
                            usability=Usability.CANNOT_RUN)
        record = vb.caskroom(intel.prefix, "iterm2")
        plan = self.adopted(intel, options={"only": "iterm2"})
        result = self.check(plan, bundle=self.bundle([self.brew, self.ports, intel]))
        self.assertEqual(result.failures, [])
        self.assertIn(("iterm2 -> iterm2", f"the record {record} of the undrivable source stays in place"),
                      self.reports(result, "installed"))
        until = self.adopted(intel, path_removed={intel.prefix: [("cask", "iterm2")]})
        result = self.check(until, bundle=self.bundle([self.brew, self.ports, intel]))
        self.assertIn(("iterm2 -> iterm2", f"the record {record} stays until phase 6 deletes {intel.prefix}"),
                      self.reports(result, "installed"))

    def test_a_macports_target_reads_a_registry_backup(self):
        target = eb.instance(self.tmp, Manager.PORTS, "opt/local-target")
        assert target.portdbpath is not None
        mb.make_registry(target.portdbpath, ports=[mb.port(1, "wget", "1.25.0"),
                                                   mb.port(2, "curl", "8.11.0", state="imaged")],
                         files=[(1, os.path.join(target.prefix, "bin", "wget"), None, 1, 1)])
        source = make_package("wget", prefix=self.ul.prefix, executables=["wget"])
        plan = self.plan(instances=[target, self.ul], target=target,
                         mappings=[vb.mapping(source, "port", "wget", version="1.25.0_0"),
                                   vb.mapping(make_package("curl", prefix=self.ul.prefix), "port", "curl",
                                              version="8.11.0_0")])
        result = self.check(plan, bundle=self.bundle([target, self.ul]))
        self.assertEqual(self.failures(result, "installed"), [f"curl is not installed in {target.prefix}"])
        self.assertEqual(self.failures(result, "commands"), [])


class CommandsTest(VerifyTest):
    """Commands provided: executables matched, renamed or lost, keg-only targets and cask artifacts"""

    def test_executables_matched_renamed_or_lost(self):
        vb.keg(self.brew.prefix, "gnu-sed", "4.9", exes=["gsed"])
        vb.keg(self.brew.prefix, "sqlite", "3.47.0", exes=["sqlite3"])
        vb.keg(self.brew.prefix, "empty-bpu", "1.0")
        self.host.info = vb.info([vb.formula("gnu-sed", ["4.9"]), vb.formula("sqlite", ["3.47.0"], keg_only=True),
                                  vb.formula("empty-bpu", ["1.0"])])
        plan = self.plan(mappings=[
            vb.mapping(self.port("gsed", executables=["gsed", "gnused-extra"]), "formula", "gnu-sed", version="4.9"),
            vb.mapping(self.port("sqlite3", executables=["sqlite3"]), "formula", "sqlite", version="3.47.0"),
            vb.mapping(self.port("empty", executables=["empty"]), "formula", "empty-bpu", version="1.0")])
        result = self.check(plan)
        bin_dir = os.path.join(self.brew.prefix, "opt", "sqlite", "bin")
        self.assertEqual(self.failures(result, "commands"), ["empty-bpu installs no executable; the source had empty"])
        self.assertEqual(self.reports(result, "commands"), [
            ("gsed -> gnu-sed", "renamed or lost: gnused-extra"),
            ("sqlite3 -> sqlite",
             f"keg-only: its executables are in {bin_dir}, which is not on PATH (the phase 7 note)")])

    def test_a_companion_s_executables_count_for_its_mapping(self):
        vb.keg(self.brew.prefix, "tcl-bpu", "9.0", exes=["tclsh"])
        vb.keg(self.brew.prefix, "tk-bpu", "9.0", exes=["wish"])
        self.host.info = vb.info([vb.formula("tcl-bpu", ["9.0"]), vb.formula("tk-bpu", ["9.0"])])
        plan = self.plan(mappings=[vb.mapping(self.port("tcltk", executables=["tclsh", "wish"]), "formula", "tcl-bpu",
                                              version="9.0", companions=["tk-bpu"])])
        result = self.check(plan)
        self.assertEqual(self.failures(result, "commands"), [])
        self.assertEqual(self.reports(result, "commands"), [])

    def test_a_cask_target_s_app_and_binary_artifacts(self):
        artifacts = [{"app": ["Zed.app"]}, {"binary": ["$APPDIR/Zed.app/Contents/MacOS/cli", {"target": "zed"}]}]
        vb.caskroom(self.brew.prefix, "zed", "0.160")
        self.host.info = vb.info(casks=[vb.cask("zed", "0.160", artifacts)])
        plan = self.plan(mappings=[vb.mapping(make_package("zed", kind="cask", prefix=self.ul.prefix), "cask", "zed")])
        app, link = os.path.join(self.apps, "Zed.app"), os.path.join(self.brew.prefix, "bin", "zed")
        self.assertEqual(self.failures(self.check(plan), "commands"),
                         [f"none of its app, suite and binary artifacts exists: {app}, {link}"])
        os.makedirs(os.path.join(app, "Contents", "MacOS"))
        result = self.check(plan)
        self.assertEqual(self.failures(result, "commands"), [])
        self.assertEqual(self.reports(result, "commands"), [("zed -> zed", f"missing artifacts: {link}")])
        with open(os.path.join(app, "Contents", "MacOS", "cli"), "w") as fh:
            fh.write("#!/bin/sh\n")
        os.symlink(os.path.join(app, "Contents", "MacOS", "cli"), link)
        self.assertEqual(self.reports(self.check(plan), "commands"), [])


class LibrariesTest(VerifyTest):
    """Variant libraries: the libraries of a root built with variants that its target lacks"""

    def test_libraries_of_a_variant_root(self):
        source = self.ports.prefix
        ports_dir = snapshot.ports_dir(self.run_dir, source)
        mb.make_registry(ports_dir, ports=[mb.port(1, "vim", "9.1.0", variants="+huge", requested_variants="+huge")],
                         files=[(1, os.path.join(source, "lib", "libvim.dylib"), None, 1, 1),
                                (1, os.path.join(source, "lib", "libxdiff.a"), None, 1, 0),
                                (1, os.path.join(source, "bin", "vim"), None, 1, 1)])
        vb.keg(self.brew.prefix, "vim", "9.1.1", exes=["vim"], libs=["libvim.dylib"])
        vb.keg(self.brew.prefix, "emacs", "30.1", exes=["emacs"])
        self.host.info = vb.info([vb.formula("vim", ["9.1.1"]), vb.formula("emacs", ["30.1"])])
        vim = self.port("vim", version="9.1.0_0+huge", spec_args=["vim", "@9.1.0_0+huge"], requested_variants=["+huge"])
        emacs = self.port("emacs", requested_variants=["+x11"])
        plan = self.plan(mappings=[vb.mapping(vim, "formula", "vim", version="9.1.1"),
                                   vb.mapping(emacs, "formula", "emacs", version="30.1")])
        result = self.check(plan)
        self.assertEqual(result.failures, [])
        self.assertEqual(self.reports(result, "libraries"), [
            ("vim -> vim", "libraries of vim +huge that vim does not install: libxdiff.a"),
            ("emacs -> emacs", "the source's file list is gone, so its libraries are not compared")])
        vb.keg(self.brew.prefix, "vim", "9.1.1", exes=["vim"], libs=["libvim.dylib", "libxdiff.a"])
        plan.mappings = plan.mappings[:1]
        self.assertEqual(self.reports(self.check(plan), "libraries"), [])


class LinkageTest(VerifyTest):
    """Clean linkage: missing references, references into what the run removes, `brew missing`"""

    def wget(self):
        """Make the target's wget keg

        @returns  the path of its `bin/wget`
        """
        keg = vb.keg(self.brew.prefix, "wget", "1.25.0", exes=["wget"])
        return os.path.join(keg, "bin", "wget")

    def test_missing_and_removed_references_fail(self):
        binary = self.wget()
        usr_local, opt_local = self.ul.prefix, self.ports.prefix
        ssl = os.path.join(vb.keg(usr_local, "openssl@3", "3.4.0", libs=["libssl.3.dylib"]), "lib", "libssl.3.dylib")
        zstd = os.path.join(vb.keg(usr_local, "zstd", "1.5.6", libs=["libzstd.1.dylib"]), "lib", "libzstd.1.dylib")
        libz = vb.macho(os.path.join(opt_local, "lib", "libz.1.dylib"))
        self.host.info = vb.info([vb.formula("wget", ["1.25.0"])])
        self.host.refs[binary] = [
            ("LC_LOAD_DYLIB", "/nonexistent-bpu/lib/libidn2.0.dylib"),
            ("LC_LOAD_DYLIB", os.path.join(usr_local, "opt", "openssl@3", "lib", "libssl.3.dylib")),
            ("LC_LOAD_DYLIB", os.path.join(usr_local, "opt", "zstd", "lib", "libzstd.1.dylib")),
            ("LC_LOAD_DYLIB", libz),
            ("LC_LOAD_WEAK_DYLIB", "/nonexistent-bpu/lib/libweak.dylib"),
            ("LC_LOAD_DYLIB", "@rpath/libnone.dylib")]
        plan = self.plan(mappings=[vb.mapping(self.port("wget"), "formula", "wget", version="1.25.0")],
                         removal_set={usr_local: [("formula", "openssl@3")]}, options={"remove_manager": opt_local})
        result = self.check(plan)
        self.assertEqual(self.failures(result, "linkage"), [
            f"{binary} references /nonexistent-bpu/lib/libidn2.0.dylib, which does not exist",
            f"{binary} references {ssl}, a file of the formula openssl@3 of {usr_local}, which phase 5 removes",
            f"{binary} references {libz}, inside {opt_local}, which phase 6 deletes"])
        self.assertEqual(self.reports(result, "linkage"), [
            ("wget", f"{binary} keeps a cross-prefix reference to {zstd}"),
            ("wget", f"{binary}: weak reference /nonexistent-bpu/lib/libweak.dylib (listed, never a failure)"),
            ("wget", f"{binary}: unresolved reference @rpath/libnone.dylib (listed, never a failure)")])

    def test_a_reference_into_a_rack_under_its_old_name_fails(self):
        binary = self.wget()
        keg = vb.keg(self.ul.prefix, "oldname", "1.0", libs=["libold.1.dylib"])
        lib = os.path.join(keg, "lib", "libold.1.dylib")
        self.host.info = vb.info([vb.formula("wget", ["1.25.0"])])
        self.host.refs[binary] = [("LC_LOAD_DYLIB", lib)]
        bundle = self.bundle()
        bundle.brew = [(self.ul, None, HomebrewInventory(instance_prefix=self.ul.prefix, kegs={"newname": [keg]}))]
        plan = self.plan(mappings=[vb.mapping(self.port("wget"), "formula", "wget", version="1.25.0")],
                         removal_set={self.ul.prefix: [("formula", "newname")]})
        self.assertEqual(self.failures(self.check(plan, bundle=bundle), "linkage"), [
            f"{binary} references {lib}, a file of the formula newname of {self.ul.prefix}, which phase 5 removes"])

    def test_a_reference_into_an_old_token_entry_fails(self):
        binary = self.wget()
        room = vb.caskroom(self.ul.prefix, "docker", "4.40.0")
        lib = vb.macho(os.path.join(room, "4.40.0", "lib", "libdocker.dylib"), 0o644)
        self.host.info = vb.info([vb.formula("wget", ["1.25.0"])])
        self.host.refs[binary] = [("LC_LOAD_DYLIB", lib)]
        bundle = self.bundle()
        bundle.brew = [(self.ul, None, HomebrewInventory(instance_prefix=self.ul.prefix,
                                                         caskrooms={"docker-desktop": room}))]
        plan = self.plan(mappings=[vb.mapping(self.port("wget"), "formula", "wget", version="1.25.0")],
                         removal_set={self.ul.prefix: [("cask", "docker-desktop")]})
        self.assertEqual(self.failures(self.check(plan, bundle=bundle), "linkage"), [
            f"{binary} references {lib}, a file of the cask docker-desktop of {self.ul.prefix}, which phase 5 removes"])

    def test_references_into_the_target_itself_pass(self):
        binary = self.wget()
        target = self.brew.prefix
        own = os.path.join(vb.keg(target, "openssl@3", "3.4.0", libs=["libssl.3.dylib"]), "lib", "libssl.3.dylib")
        self.host.info = vb.info([vb.formula("wget", ["1.25.0"], runtime=["openssl@3"]),
                                  vb.formula("openssl@3", ["3.4.0"])])
        self.host.refs[binary] = [("LC_LOAD_DYLIB", os.path.join(target, "opt", "openssl@3", "lib", "libssl.3.dylib"))]
        plan = self.plan(mappings=[vb.mapping(self.port("wget"), "formula", "wget", version="1.25.0")],
                         removal_set={self.ul.prefix: [("formula", "openssl@3")]})
        result = self.check(plan)
        self.assertTrue(os.path.exists(own))
        self.assertEqual((self.failures(result, "linkage"), self.reports(result, "linkage")), ([], []))

    def test_upgrade_dependents_and_rebuilds_are_scanned(self):
        binaries = {name: os.path.join(vb.keg(self.brew.prefix, name, version, exes=[name]), "bin", name)
                    for name, version in (("curl", "8.11.0"), ("git", "2.47.0"), ("zlib-tool", "1.3"))}
        self.host.info = vb.info([vb.formula("curl", ["8.11.0"], runtime=["openssl@3"]),
                                  vb.formula("git", ["2.47.0"]), vb.formula("zlib-tool", ["1.3"])])
        for path in binaries.values():
            self.host.refs[path] = [("LC_LOAD_DYLIB", "/nonexistent-bpu/lib/libgone.dylib")]
        assert self.brew.binary is not None
        reinstall = Action(action_id="3.git.rebuild", kind="command", sudo=False, description="rebuild git",
                           argv=[self.brew.binary, "reinstall", "--formula", "git"],
                           instance_prefix=self.brew.prefix)
        plan = self.plan(target_upgrades=["openssl@3"], phases=[Phase(3, "install", [reinstall], False)])
        self.assertEqual(verify.rebuilt_names(plan, self.brew.prefix), ["git"])
        result = self.check(plan)
        self.assertEqual(sorted(f.subject for f in result.failures if f.step == "linkage"), ["curl", "git"])

    def upgrade(self, action_id, *words):
        """Return a phase 3 upgrade of the target

        @param action_id  the action's id
        @param words      the words after `brew upgrade`
        @returns          the action
        """
        assert self.brew.binary is not None
        return Action(action_id=action_id, kind="command", sudo=False, description="upgrade",
                      argv=[self.brew.binary, "upgrade", *words], instance_prefix=self.brew.prefix)

    def test_an_upgraded_app_is_not_read_as_a_formula(self):
        plan = self.plan(phases=[Phase(3, "install", [self.upgrade("3.upgrade.casks", "--cask", "firefox"),
                                                      self.upgrade("3.upgrade.others", "--formula", "pkgconf")],
                                       False)])
        self.assertEqual(verify.rebuilt_names(plan, self.brew.prefix), ["pkgconf"])

    def test_a_break_under_an_added_upgrade_is_a_task(self):
        # curl uses openssl@3, which a replacement needs. Only --upgrade-all upgrades pkgconf, which gawk uses.
        binaries = {name: os.path.join(vb.keg(self.brew.prefix, name, "1.0", exes=[name]), "bin", name)
                    for name in ("curl", "pkgconf", "gawk")}
        self.host.info = vb.info([vb.formula("curl", ["1.0"], runtime=["openssl@3"]), vb.formula("pkgconf", ["1.0"]),
                                  vb.formula("gawk", ["1.0"], runtime=["pkgconf"])])
        for path in binaries.values():
            self.host.refs[path] = [("LC_LOAD_DYLIB", "/nonexistent-bpu/lib/libgone.dylib")]
        plan = self.plan(target_upgrades=["openssl@3", "pkgconf"], optional_upgrades=["pkgconf"],
                         phases=[Phase(3, "install", [self.upgrade("3.upgrade.others", "--formula", "pkgconf")],
                                       False)])
        gone = "references /nonexistent-bpu/lib/libgone.dylib, which does not exist"
        left = "left it without a library it needs"
        brew = self.brew.binary
        for gate in (True, False):
            result = self.check(plan, gate=gate)
            self.assertEqual([(f.subject, f.text) for f in result.failures if f.step == "linkage"],
                             [("curl", f"{binaries['curl']} {gone}")])
            self.assertEqual(result.tasks, {
                "pkgconf": f"Install pkgconf again, because its upgrade, which --upgrade-all asked for, {left}: "
                           f"{brew} reinstall --formula pkgconf",
                "gawk": f"Install gawk again, because --upgrade-all upgraded a package it uses, which {left}: "
                        f"{brew} reinstall --formula gawk"})
            self.assertIn(("gawk", f"{binaries['gawk']} {gone} (for you to repair; the move does not need it)"),
                          self.reports(result, "linkage"))
        self.assertEqual(result.lines()[-3:], ["For you to do:"] + [f"  {task}" for task in result.tasks.values()])

    def test_a_package_none_of_whose_binaries_otool_reads_fails(self):
        binary = self.wget()
        git = vb.keg(self.brew.prefix, "git", "2.47.0", exes=["git", "scalar"])
        curl = vb.keg(self.brew.prefix, "curl", "8.11.0", exes=["curl", "curl-config"])
        config = os.path.join(curl, "bin", "curl-config")
        self.host.info = vb.info([vb.formula(n, [v]) for n, v in (("wget", "1.25.0"), ("git", "2.47.0"),
                                                                  ("curl", "8.11.0"))])
        self.host.unreadable = {binary, os.path.join(git, "bin", "git"), os.path.join(git, "bin", "scalar"), config}
        plan = self.plan(mappings=[vb.mapping(self.port(n), "formula", n, version=v)
                                   for n, v in (("wget", "1.25.0"), ("git", "2.47.0"), ("curl", "8.11.0"))])
        for gate in (True, False):
            result = self.check(plan, gate=gate)
            self.assertEqual([(f.subject, f.text) for f in result.failures if f.step == "linkage"], [
                ("wget", "otool -l could not read its binary (no otool output), so its linkage is unknown"),
                ("git", "otool -l could not read any of its 2 binaries (no otool output), so its linkage is unknown")])
            self.assertIn(("curl", f"{config}: no otool output"), self.reports(result, "linkage"))

    def test_brew_missing_and_other_breakage_reported(self):
        self.host.missing = r.FakeResponse(exit=1, stdout="wget: libidn2\n")
        bundle = self.bundle()
        bundle.result.linkage = {"packages": {f"{self.brew.prefix}|formula|sqlite": {"broken": ["x"]},
                                              f"{self.ul.prefix}|formula|old": {"broken": ["y"]}}}
        result = self.check(self.plan(), bundle=bundle)
        self.assertEqual(result.failures, [])
        self.assertEqual(self.reports(result, "linkage"), [
            ("brew missing", "wget: libidn2"),
            ("sqlite", "brew-broken-linkage: 1 binaries with broken references (never a failure here)")])
        missing = [a for a in self.fake.actions if a.argv[-1] == "missing"]
        self.assertEqual((missing[0].read_only, missing[0].on_failure), (True, OnFailure.PROBE))


class ServicesTest(VerifyTest):
    """Services replaced: each owned source service with its target's service or a manual note"""

    def test_source_services_get_a_target_service(self):
        source = self.ports.prefix
        data = os.path.join(source, "var", "db", "postgresql16")
        plist = os.path.join(source, "etc", "LaunchDaemons", "org.macports.postgresql16-server.plist")
        svc = db.service("org.macports.postgresql16-server", plist, source, package="postgresql16-server",
                         kind="port", scope="system", data_dirs=[data])
        job = db.service("com.example.mine", "/Library/LaunchDaemons/com.example.mine.plist", source, owned=False,
                         package=None)
        pg = self.port("postgresql16-server", services=[svc, job])
        memcached = self.port("memcached", services=[db.service("org.macports.memcached", plist, source,
                                                                package="memcached", kind="port")])
        plan = self.plan(roots=[pg, memcached], mappings=[vb.mapping(pg, "formula", "postgresql@16", version="16.4")],
                         removal_set={source: [("port", "postgresql16-server"), ("port", "memcached")]})
        bundle = self.bundle()
        catalogue = Catalogue(formulae={"postgresql@16": {"service_args": [[":run_type", ":immediate"]]}})
        bundle.brew = [(self.brew, catalogue, None)]
        result = self.check(plan, bundle=bundle)
        self.assertEqual(self.reports(result, "services"), [
            ("org.macports.postgresql16-server", "the target postgresql@16 has a service: `brew services start "
             f"postgresql@16` (data in {data})"),
            ("org.macports.memcached", "memcached has no replacement in the target: start what it ran by hand")])

    def test_data_phase_6_archived_and_deleted_is_in_its_archive(self):
        source = self.ports.prefix
        gone, kept = os.path.join(source, "var", "lib", "dbus"), os.path.join(source, "var", "lib", "kept")
        os.makedirs(kept)
        archive = os.path.join(self.run_dir.path, "data-archive", state.slug(os.path.join(source, "var", "lib")))
        os.makedirs(os.path.dirname(archive))
        with open(archive + ".tar.gz", "wb") as fh:
            fh.write(b"\x1f\x8b")
        agents = os.path.join(self.home, "Library", "LaunchAgents")
        svc = db.service("org.freedesktop.dbus-session", os.path.join(agents, "org.freedesktop.dbus-session.plist"),
                         source, package="dbus", kind="port", data_dirs=[gone, kept])
        dbus = self.port("dbus", services=[svc])
        plan = self.plan(roots=[dbus], mappings=[vb.mapping(dbus, "formula", "dbus", version="1.16.2")],
                         removal_set={source: [("port", "dbus")]})
        self.assertEqual(self.reports(self.check(plan), "services"), [
            ("org.freedesktop.dbus-session", f"no service is known for the target dbus: start it by hand (data in "
             f"{kept}) (data of {gone} archived in {archive}.tar.gz)")])

    def test_data_phase_6_deleted_without_an_archive_says_so(self):
        source = self.ports.prefix
        logs = os.path.join(source, "var", "log", "dbus")
        self.run_dir.journal.append({"phase": 6, "action_id": f"6.delete.{state.slug(source)}", "result": "ok"})
        agents = os.path.join(self.home, "Library", "LaunchAgents")
        svc = db.service("org.freedesktop.dbus-session", os.path.join(agents, "org.freedesktop.dbus-session.plist"),
                         source, package="dbus", kind="port", data_dirs=[logs])
        dbus = self.port("dbus", services=[svc])
        plan = self.plan(roots=[dbus], mappings=[vb.mapping(dbus, "formula", "dbus", version="1.16.2")],
                         removal_set={source: [("port", "dbus")]})
        self.assertEqual(self.reports(self.check(plan), "services"), [
            ("org.freedesktop.dbus-session", "no service is known for the target dbus: start it by hand (data of "
             f"{logs} deleted by phase 6 without an archive)")])


class LoginPathTest(VerifyTest):
    """Login shell PATH: removed prefixes in it, the primary survivor's order, and its stderr lines"""

    def setUp(self):
        super().setUp()
        self.shell = self.path("bin", "zsh")
        os.makedirs(os.path.dirname(self.shell))
        with open(self.shell, "w") as fh:
            fh.write("")
        self.gone = eb.instance(self.tmp, Manager.BREW, "usr/local-gone", roots=eb.USR_LOCAL_ROOTS, exists=False)

    def login(self, stdout, stderr=""):
        """Check a plan with a removed Homebrew prefix that is gone, and a login shell that prints the given output

        @param stdout  what the login shell prints: its PATH
        @param stderr  what it prints on its error stream
        @returns       the result
        """
        self.host.login = r.FakeResponse(stdout=stdout, stderr=stderr)
        plan = self.plan(instances=[self.brew, self.ports, self.gone])
        bundle = self.bundle([self.brew, self.ports], [self.port("jq")], login_shell=self.shell)
        bundle.result.environment.update({"zdotdir": os.path.join(self.home, "zd"), "zdotdir_source": "environment"})
        return self.check(plan, bundle=bundle)

    def test_removed_entries_order_and_stderr(self):
        gone, opt_homebrew, opt_local = self.gone.prefix, self.brew.prefix, self.ports.prefix
        result = self.login(f"\x1b]0;zsh\x07\n{gone}/opt/coreutils/libexec/gnubin:{opt_local}/bin:{opt_homebrew}/bin:"
                            "/usr/bin:/bin\n",
                            f"zsh: command not found: brew\n{gone}/opt/fzf/shell/x.zsh: No such file or directory\n"
                            f"{gone}/etc/bashrc.d/y: not under an owned root\nfine\n")
        self.assertTrue(result.ok)
        self.assertEqual(self.reports(result, "login-path"), [
            (f"{gone}/opt/coreutils/libexec/gnubin", f"the login PATH holds this entry of the removed {gone}"),
            (opt_homebrew, f"the login PATH lists {opt_local}/bin before {opt_homebrew}/bin"),
            (self.shell, "stderr: zsh: command not found: brew"),
            (self.shell, f"stderr: {gone}/opt/fzf/shell/x.zsh: No such file or directory")])
        [action] = [a for a in self.fake.actions if a.argv[0] == verify.ENV]
        self.assertEqual(action.argv, [verify.ENV, "TERM=dumb", f"ZDOTDIR={os.path.join(self.home, 'zd')}",
                                       self.shell, "-l", "-i", "-c", "echo $PATH"])
        self.assertEqual((action.new_session, action.read_only, action.timeout_s, action.on_failure, action.sudo),
                         (True, True, 120, OnFailure.PROBE, False))

    def test_a_clean_login_path_reports_nothing(self):
        opt_homebrew, opt_local = self.brew.prefix, self.ports.prefix
        result = self.login(f"{opt_homebrew}/bin:{opt_homebrew}/sbin:{opt_local}/bin:/usr/bin:/bin\n")
        self.assertEqual(self.reports(result, "login-path"), [])

    def test_a_login_shell_that_is_gone_is_reported(self):
        result = self.check(self.plan(), bundle=self.bundle(login_shell="/nonexistent-bpu/bin/zsh"))
        self.assertEqual(self.reports(result, "login-path"),
                         [("/nonexistent-bpu/bin/zsh", "not found, so the login PATH is not checked")])


class LanguagePackagesTest(VerifyTest):
    """Language packages: the requirements files kept, and the `pipx install`s that failed"""

    def test_requirements_files_and_pipx_installs(self):
        extras = {"python": [{"version": "3.12", "instance_prefix": self.ports.prefix, "site_packages": "x",
                              "dists": [{"name": "requests", "version": "2.31.0"}]}],
                  "npm": [{"name": "typescript", "version": "5.6.0", "instance_prefix": self.ports.prefix}]}
        self.run_dir.write_json("scan.json", json.dumps({"interpreter_extras": extras}))
        kept = self.run_dir.sub("requirements-python3.12.txt")
        with open(kept, "w") as fh:
            fh.write("requests==2.31.0\n")
        pipx_bin = os.path.join(self.brew.prefix, "bin", "pipx")
        pipx = Action(action_id="3.pipx.black", kind="command", sudo=False, description="pipx install black",
                      argv=["/usr/bin/arch", "-arm64", pipx_bin, "install", "black"], instance_prefix=self.brew.prefix)
        self.run_dir.journal.append({"phase": 3, "action_id": "3.pipx.black", "result": "failed"})
        result = self.check(self.plan(phases=[Phase(3, "install", [pipx], False)]))
        self.assertEqual(self.reports(result, "language-packages"), [
            ("npm-globals.txt", "missing: no requirements file for an interpreter with extras"),
            ("requirements-python3.12.txt", f"kept in {kept}"),
            ("black", "pipx install did not succeed (failed)")])
        self.assertTrue(result.ok)


class RemovedTest(VerifyTest):
    """Sources removed: Cellar, Caskroom and registry entries of the removal set that are left"""

    def test_removal_set_pairs_still_installed_fail(self):
        usr_local, opt_local = self.ul.prefix, self.ports.prefix
        vb.keg(usr_local, "wget", "1.25.0")
        vb.caskroom(usr_local, "firefox")
        vb.caskroom(usr_local, "htop")
        assert self.ports.portdbpath is not None
        mb.make_registry(self.ports.portdbpath, ports=[mb.port(1, "zlib", "1.3.1", state="imaged")])
        gone = eb.instance(self.tmp, Manager.PORTS, "opt/gone", exists=False)
        plan = self.plan(instances=[self.brew, self.ports, self.ul, gone], removal_set={
            usr_local: [("formula", "wget"), ("cask", "firefox"), ("formula", "jq"), ("formula", "htop")],
            opt_local: [("port", "zlib"), ("port", "gone")], gone.prefix: [("port", "zlib")]})
        result = self.check(plan)
        self.assertEqual(self.failures(result, "removed"), [
            f"still installed in {opt_local}: zlib @1.3.1_0",
            f"the formula is still installed in {usr_local}", f"the cask is still installed in {usr_local}"])

    def test_nothing_left_passes(self):
        plan = self.plan(removal_set={self.ul.prefix: [("formula", "wget")], self.ports.prefix: [("port", "zlib")]})
        self.assertEqual(self.failures(self.check(plan), "removed"), [])

    def test_a_formula_left_in_a_rack_under_its_old_name_fails(self):
        keg = vb.keg(self.ul.prefix, "oldname", "1.0")
        bundle = self.bundle()
        bundle.brew = [(self.ul, None, HomebrewInventory(instance_prefix=self.ul.prefix, kegs={"newname": [keg]}))]
        plan = self.plan(removal_set={self.ul.prefix: [("formula", "newname")]})
        self.assertEqual(self.failures(self.check(plan, bundle=bundle), "removed"),
                         [f"the formula is still installed in {self.ul.prefix}"])

    def test_a_cask_left_under_its_old_token_fails(self):
        room = vb.caskroom(self.ul.prefix, "docker")
        bundle = self.bundle()
        bundle.brew = [(self.ul, None, HomebrewInventory(instance_prefix=self.ul.prefix,
                                                         caskrooms={"docker-desktop": room}))]
        plan = self.plan(removal_set={self.ul.prefix: [("cask", "docker-desktop")]})
        self.assertEqual(self.failures(self.check(plan, bundle=bundle), "removed"),
                         [f"the cask is still installed in {self.ul.prefix}"])


class GateTest(VerifyTest):
    """The gate's own checks: the packages active before the run, and `target_upgrades`"""

    def snapshot_json(self, data):
        """Write the target's `installed.json` of phase 1 into the run's snapshot

        @param data  the `brew info --json=v2 --installed` value
        """
        sub = snapshot.brew_dir(self.run_dir, self.brew.prefix)
        os.makedirs(sub)
        with open(os.path.join(sub, snapshot.INSTALLED_JSON), "w") as fh:
            json.dump(data, fh)

    def test_pre_existing_packages_and_target_upgrades(self):
        self.snapshot_json({"formulae": [vb.formula("git", ["2.47.0"]), vb.formula("sqlite", ["3.47.0"], linked=False,
                                                                                     keg_only=True)],
                            "casks": [vb.cask("firefox")]})
        vb.keg(self.brew.prefix, "git", "2.47.0", exes=["git"])
        vb.caskroom(self.brew.prefix, "firefox")
        self.host.info = vb.info([vb.formula("git", ["2.47.0"])], [vb.cask("firefox")])
        result = self.check(self.plan(target_upgrades=["openssl@3"]), gate=True)
        self.assertEqual([(f.step, f.subject) for f in result.failures], [("gate", "sqlite"), ("gate", "openssl@3")])
        self.assertIn(f"rollback {self.run_dir.run_id}", result.failures[0].text)
        self.assertEqual(result.lines()[0], "gate: 2 failures")
        self.assertFalse([a for a in self.fake.actions if a.argv[0] == verify.ENV])

    def test_a_package_lost_to_an_added_upgrade_is_a_task(self):
        self.snapshot_json({"formulae": [vb.formula("pkgconf", ["2.4.0"]), vb.formula("ddrescue", ["1.28"])],
                            "casks": [vb.cask("firefox")]})
        vb.keg(self.brew.prefix, "ddrescue", "1.29", exes=["ddrescue"])
        self.host.info = vb.info([vb.formula("ddrescue", ["1.29"], linked=False)])
        plan = self.plan(target_upgrades=["pkgconf", "ddrescue"], optional_upgrades=["pkgconf", "ddrescue"],
                         optional_casks=["firefox"])
        result = self.check(plan, gate=True)
        self.assertEqual(result.lines()[0], "gate: passed")
        brew, where = self.brew.binary, f"Homebrew at {self.brew.prefix}"
        left = "because its upgrade, which --upgrade-all asked for, left it"
        self.assertEqual(result.tasks, {
            "pkgconf": f"Install pkgconf again, {left} uninstalled in {where}: {brew} install --formula pkgconf",
            "ddrescue": f"Link ddrescue again, {left} installed, but not linked into {where}: {brew} link ddrescue",
            "the app firefox": f"Install the app firefox again, {left} uninstalled in {where}: "
                               f"{brew} install --cask firefox"})
        self.assertEqual(self.reports(result, "gate")[0], (
            "pkgconf", f"is uninstalled in {where} after its upgrade (for you to repair; the move does not need it)"))
        # The same losses stop the run when the move needs the packages.
        needed = self.check(self.plan(target_upgrades=["pkgconf", "ddrescue"]), gate=True)
        self.assertEqual([f.subject for f in needed.failures], ["pkgconf", "ddrescue", "firefox", "pkgconf"])
        self.assertEqual(needed.tasks, {})

    def test_a_port_lost_to_an_added_upgrade_names_the_port_command(self):
        target = eb.instance(self.tmp, Manager.PORTS, "opt/local-target")
        assert target.portdbpath is not None
        binary = vb.macho(os.path.join(target.prefix, "bin", "jq"))
        mb.make_registry(target.portdbpath, files=[(2, binary, None, 1, 1)], deps=[(2, "oniguruma")],
                         ports=[mb.port(1, "gawk", "5.3.1", state="imaged"), mb.port(2, "jq", "1.8"),
                                mb.port(3, "oniguruma", "6.9.9")])
        self.host.refs[binary] = [("LC_LOAD_DYLIB", "/nonexistent-bpu/lib/libonig.5.dylib")]
        sub = snapshot.ports_dir(self.run_dir, target.prefix)
        os.makedirs(sub)
        with open(os.path.join(sub, snapshot.INSTALLED), "w") as fh:
            fh.write(snapshot.INSTALLED_HEADER + "\ngawk\t5.3.0_0\ttrue\t\ttrue\t24\nzlib\t1.3_0\ttrue\t\ttrue\t24\n"
                     "jq\t1.8_0\ttrue\t\ttrue\t24\n")
        plan = self.plan(instances=[target, self.ul], target=target, target_upgrades=["gawk", "zlib", "oniguruma"],
                         optional_upgrades=["gawk", "zlib", "oniguruma"])
        result = self.check(plan, gate=True, bundle=self.bundle([target, self.ul]))
        self.assertEqual(result.lines()[0], "gate: passed")
        port, where = f"sudo {target.binary}", f"MacPorts at {target.prefix}"
        asked = "because its upgrade, which --upgrade-all asked for, left it"
        # jq only uses a port of the option. A Homebrew is still installed, so a build runs in trace mode.
        self.assertEqual(result.tasks, {
            "jq": "Install jq again, because --upgrade-all upgraded a package it uses, which left it without a "
                  f"library it needs: {port} -n -t upgrade --force jq",
            "gawk": f"Switch gawk on again, {asked} stored in {where}, but switched off: {port} activate gawk",
            "zlib": f"Install zlib again, {asked} uninstalled in {where}: {port} -t install zlib"})
        # Once the Homebrew is gone, the same build runs without trace mode.
        alone = self.check(plan, gate=True, bundle=self.bundle([target]))
        self.assertEqual(alone.tasks["zlib"],
                         f"Install zlib again, {asked} uninstalled in {where}: {port} install zlib")

    def test_formulae_list_stands_in_for_installed_json(self):
        sub = snapshot.brew_dir(self.run_dir, self.brew.prefix)
        os.makedirs(sub)
        with open(os.path.join(sub, snapshot.FORMULAE), "w") as fh:
            fh.write(snapshot.FORMULAE_HEADER + "\ngit\ttrue\thomebrew/core\t2.47.0\n")
        self.host.info = vb.info([vb.formula("git", ["2.47.0"], linked=False)])
        self.assertTrue(self.check(self.plan(), gate=True).ok)

    def test_a_gate_without_the_snapshot_fails(self):
        result = self.check(self.plan(), gate=True)
        self.assertEqual(self.failures(result, "gate"),
                         [f"the phase 1 snapshot of the target is missing from {self.run_dir.path}"])

    def test_a_replacement_neither_linked_nor_keg_only_fails(self):
        self.snapshot_json({"formulae": [], "casks": []})
        vb.keg(self.brew.prefix, "wget", "1.25.0", exes=["wget"])
        vb.keg(self.brew.prefix, "sqlite", "3.47.0", exes=["sqlite3"])
        self.host.info = vb.info([vb.formula("wget", ["1.25.0"], linked=False),
                                  vb.formula("sqlite", ["3.47.0"], linked=False, keg_only=True)])
        plan = self.plan(mappings=[
            vb.mapping(self.port("wget", executables=["wget"]), "formula", "wget", version="1.25.0"),
            vb.mapping(self.port("sqlite3", executables=["sqlite3"]), "formula", "sqlite", version="3.47.0")])
        unlinked = [("installed", "wget -> wget", f"wget is installed in {self.brew.prefix} but neither linked nor "
                     "keg-only: `brew link wget` links it")]
        for gate in (True, False):
            result = self.check(plan, gate=gate)
            self.assertEqual([(f.step, f.subject, f.text) for f in result.failures], unlinked)
        self.host.info = vb.info([vb.formula("wget", ["1.25.0"]),
                                  vb.formula("sqlite", ["3.47.0"], linked=False, keg_only=True)])
        self.assertTrue(self.check(plan, gate=True).ok)


class CommandTest(VerifyTest):
    """`brew-ports verify`: the plan it takes, the dirty marker it ignores, and its exit codes"""

    console: db.QuietConsole        # what the last command printed

    def verify_cmd(self, bundle, plan_arg=None):
        """Run `brew-ports verify` over a scan, printing into a new `console`

        @param bundle    the scan the command takes
        @param plan_arg  the PLAN argument, or None for the newest run's plan
        @returns         the exit code
        """
        self.console = eb.QuietConsole()
        ctx = Context(argparse.Namespace(command="verify", plan=plan_arg), self.console, self.sd, tty=False,
                      environ={"HOME": self.home})

        def make(given, run_dir):
            self.run_dir = run_dir
            return self.runner(console=given.console)
        with mock.patch("brew_ports.scan.build", return_value=bundle):
            return verify.cmd_verify(ctx, make_runner=make)

    def test_newest_plan_verified_despite_dirty_marker(self):
        plan = self.plan(mappings=[vb.mapping(self.port("wget"), "formula", "wget", version="1.25.0")])
        eb.write_run(self.sd, "20000101-000000-aaaaaa", plan)
        self.sd.touch_dirty("20991231-000000-ffffff", "doctor --fix")
        vb.keg(self.brew.prefix, "wget", "1.25.0", exes=["wget"])
        self.host.info = vb.info([vb.formula("wget", ["1.25.0"])])
        self.assertEqual(self.verify_cmd(self.bundle()), verify.EXIT_OK)
        self.assertIn("verify: passed", self.console.text)
        with open(self.run_dir.sub("report.md"), encoding="utf-8") as fh:
            self.assertIn("verify: passed", fh.read())
        self.host.info = vb.info([])
        path = os.path.join(self.sd.runs, "20000101-000000-aaaaaa", "plan.json")
        self.assertEqual(self.verify_cmd(self.bundle(), plan_arg=path), verify.EXIT_VERIFY)
        self.assertIn("FAIL wget -> wget (replacements installed): wget is not installed", self.console.text)

    def test_no_plan_is_a_usage_error(self):
        self.assertEqual(self.verify_cmd(self.bundle()), verify.EXIT_USAGE)
        self.assertEqual(self.verify_cmd(self.bundle(), plan_arg=self.path("nope.json")), verify.EXIT_USAGE)

    def test_a_plan_with_a_malformed_field_is_a_usage_error(self):
        path = eb.write_run(self.sd, "20000101-000000-aaaaaa", self.plan()).sub("plan.json")
        eb.malform_plan(path)
        self.assertEqual(self.verify_cmd(self.bundle(), plan_arg=path), verify.EXIT_USAGE)
        self.assertIn(f"brew-ports verify: {path} is not a plan", self.console.text)


if __name__ == "__main__":
    unittest.main()

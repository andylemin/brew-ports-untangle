"""Locating MacPorts: macports.conf, base's files, the usability of each instance and the target choice"""

import os
import unittest
from unittest import mock

from brew_ports import runner as r
from brew_ports.macports import locate, registry
from brew_ports.model import Manager, Usability
from tests.unit.fixtures.macports.builders import fake_runner, make_prefix, make_registry, port
from tests.unit.helpers import TempDirTest, make_instance


def mode_executable(path):
    """Return whether a path is a regular file with an execute bit, the mode alone deciding

    @param path  the path
    @returns     True for a file with any execute bit set
    """
    return os.path.isfile(path) and bool(os.stat(path).st_mode & 0o111)


class ConfigTest(TempDirTest):
    """macports.conf as base reads it, the user's file, macports_autoconf.tcl, the receipt version and `lipo`"""

    def test_parse_conf_as_base_reads_it(self):
        path = self.write("macports.conf", "# comment\nprefix              \t/opt/local\n  indented value\n"
                                           "portdbpath /opt/local/var/macports # not a comment\n"
                                           "binpath /a:\\\n/b\nempty\n")
        conf = locate.parse_conf(path)
        self.assertEqual(conf["prefix"], "/opt/local")
        self.assertEqual(conf["portdbpath"], "/opt/local/var/macports # not a comment")
        self.assertEqual(conf["binpath"], "/a: /b")
        self.assertEqual(conf["empty"], "")
        self.assertNotIn("indented", conf)
        self.assertEqual(locate.parse_conf(self.path("missing.conf")), {})

    def test_user_conf_overrides_the_global_one(self):
        prefix = make_prefix(self.path("opt", "local"))
        home = self.path("home")
        self.write("home/.macports/macports.conf", "applications_dir /Users/alice/Applications/MacPorts\n")
        conf = locate.read_config(prefix, {"HOME": home})
        self.assertEqual(conf["applications_dir"], "/Users/alice/Applications/MacPorts")
        self.assertEqual(conf["portdbpath"], os.path.join(prefix, "var", "macports"))
        self.assertEqual(conf["sources_conf"], os.path.join(prefix, "etc", "macports", "sources.conf"))
        self.assertEqual(locate.read_config(prefix, {"HOME": self.path("nobody")})["applications_dir"],
                         "/Applications/MacPorts")

    def test_autoconf(self):
        prefix = make_prefix(self.path("opt", "local"), version="2.8.1", os_major="22")
        auto = locate.read_autoconf(prefix)
        self.assertEqual((auto["macports_version"], auto["os_platform"], auto["os_major"]), ("2.8.1", "darwin", "22"))
        self.assertEqual(locate.read_autoconf(self.path("none")), {})

    def test_package_version(self):
        info = "package-id: org.macports.MacPorts\nversion: 0.2.8.1.0.0.0.0.0\nvolume: /\nlocation: \n"
        self.assertEqual(locate.decode_pkg_version(info), "2.8.1")
        self.assertEqual(locate.decode_pkg_version("version: 0.2.10.0.0.0.0.0.0\n"), "2.10.0")
        self.assertEqual(locate.decode_pkg_version("version: 0.2.12.7\n"), "2.12.7")
        self.assertIsNone(locate.decode_pkg_version("version: 2.8.1\n"))
        self.assertIsNone(locate.decode_pkg_version("volume: /\n"))

    def test_features(self):
        self.assertEqual(locate.features_for("2.8.1"), ())
        self.assertEqual(locate.features_for("2.9.3"), ())
        self.assertEqual(locate.features_for("2.10.0"), ("migrate", "snapshot"))
        self.assertEqual(locate.features_for("2.10.7"), ("migrate", "snapshot"))
        self.assertEqual(locate.features_for("2.11.0"), ("migrate", "snapshot", "snapshot_export"))
        self.assertEqual(locate.features_for(None), ())

    def test_arch_from_lipo(self):
        self.assertEqual(locate.arch_from_lipo("x86_64 arm64\n", "arm64"), "arm64")
        self.assertEqual(locate.arch_from_lipo("x86_64 arm64\n", "x86_64"), "x86_64")
        self.assertEqual(locate.arch_from_lipo("x86_64\n", "arm64"), "x86_64")
        self.assertEqual(locate.arch_from_lipo("arm64e\n", "arm64"), "arm64")
        self.assertIsNone(locate.arch_from_lipo("", "arm64"))


class BaseFilesTest(TempDirTest):
    """Base's own files: the trees, programs and man pages it owns, and the receipt from `pkgutil`"""

    def test_base_owns_its_own_files(self):
        base = locate.BaseFiles("/opt/local", frozenset({"/opt/local/lib/.turd_MacPorts"}))
        for path in ("/opt/local/bin/port", "/opt/local/bin/port-tclsh", "/opt/local/bin/daemondo",
                     "/opt/local/libexec/macports/lib/macports1.0/macports.tcl", "/opt/local/var/macports/registry/x",
                     "/opt/local/share/man/man1/port-install.1.gz", "/opt/local/share/man/man5/macports.conf.5.gz",
                     "/opt/local/share/man/man7/portfile.7.gz", "/opt/local/lib/.turd_MacPorts",
                     "/opt/local/etc/macports/macports.conf", "/opt/local/share/macports/resources/x"):
            with self.subTest(path=path):
                self.assertTrue(base.owns(path))
        for path in ("/opt/local/bin/wget", "/opt/local/lib/libz.dylib", "/opt/local/libexec/other",
                     "/opt/local/share/man/man1/wget.1.gz", "/usr/local/bin/port", "/opt/localx/bin/port"):
            with self.subTest(path=path):
                self.assertFalse(base.owns(path))

    def test_receipt_files_from_pkgutil(self):
        fake = fake_runner(self.tmp, {("/usr/sbin/pkgutil", "--files", "org.macports.MacPorts"):
                                      r.FakeResponse(stdout="opt\nopt/local\nopt/local/sbin/.turd_MacPorts\n")})
        self.assertEqual(locate.receipt_files(fake), {"/opt", "/opt/local", "/opt/local/sbin/.turd_MacPorts"})
        self.assertEqual(locate.receipt_files(fake_runner(self.tmp)), frozenset())


class FindTest(TempDirTest):
    """Instances located in temporary prefixes, and the usability their probes decide"""

    def setUp(self):
        super().setUp()
        self.runner = fake_runner(self.tmp)            # replaced by the runner of each find()
        self.home = self.path("home")
        os.makedirs(self.home)
        self.etc_paths = self.write("etc/paths", "/usr/local/bin\n/usr/bin\n/bin\n")
        self.prefix = self.path("opt", "local")

    def responses(self, prefix=None, lipo="x86_64 arm64\n", version=None, arch="-arm64"):
        """Return the responses of one prefix's probes: `lipo -archs` of its tclsh and `port -N version`

        @param prefix   the MacPorts prefix; None for the test's
        @param lipo     the output of `lipo -archs`
        @param version  the response of `port -N version`; None for a 2.12.7 base that runs
        @param arch     the `arch` flag `port` runs under; None for no `arch`
        @returns        the responses, keyed by argv
        """
        prefix = prefix or self.prefix
        out: dict[tuple[str, ...], r.FakeResponse] = {
            ("/usr/bin/lipo", "-archs", os.path.join(prefix, locate.TCLSH_REL)): r.FakeResponse(stdout=lipo)}
        argv: tuple[str, ...] = (os.path.join(prefix, "bin", "port"), "-N", "version")
        if arch:
            argv = ("/usr/bin/arch", arch) + argv
        out[argv] = version or r.FakeResponse(stdout="Version: 2.12.7\n")
        return out

    def find(self, responses, host_arch="arm64", path="", **kw):
        """Locate the instances with a fake runner, which the test keeps

        @param responses  the fake runner's responses
        @param host_arch  the host's architecture
        @param path       the `PATH` of the environment
        @param kw         further `find_instances` arguments
        @returns          the instances
        """
        fake = fake_runner(self.tmp, responses, home=self.home, host_arch=host_arch)
        self.runner = fake
        # The mode bits, not access(2): a noexec /tmp, as in the test container, refuses X_OK.
        with mock.patch.object(locate, "_executable", mode_executable):
            return locate.find_instances(fake, {"HOME": self.home, "PATH": path}, host_arch, platform=("darwin", 25),
                                         default_prefix=self.prefix, etc_paths=self.etc_paths, **kw)

    def one(self, responses, **kw):
        """Locate the instances and assert that there is exactly one

        @param responses  the fake runner's responses
        @param kw         further `find` arguments
        @returns          the instance
        """
        found = self.find(responses, **kw)
        self.assertEqual(len(found), 1)
        return found[0]

    def registry(self, prefix=None, **kw):
        """Create the registry.db of a prefix

        @param prefix  the MacPorts prefix; None for the test's
        @param kw      the `make_registry` arguments
        @returns       the path of registry.db
        """
        prefix = prefix or self.prefix
        return make_registry(os.path.join(prefix, "var", "macports"), **kw)

    def test_usable_instance(self):
        make_prefix(self.prefix)
        self.registry(ports=[port(1, "wget", "1.25.0")])
        inst = self.one(self.responses())
        self.assertEqual((inst.usability, inst.drivable, inst.inventory_known), (Usability.USABLE, True, True))
        self.assertEqual((inst.manager, inst.version, inst.arch), (Manager.PORTS, "2.12.7", "arm64"))
        self.assertEqual(inst.features, ("migrate", "snapshot", "snapshot_export"))
        self.assertEqual(inst.portdbpath, os.path.join(self.prefix, "var", "macports"))
        self.assertEqual(inst.applications_dir, "/Applications/MacPorts")
        self.assertEqual(inst.binary, os.path.join(self.prefix, "bin", "port"))
        self.assertEqual((inst.owned_roots, inst.inventory_error), ((self.prefix,), None))
        self.assertEqual(inst.identity, (os.stat(self.prefix).st_dev, os.stat(self.prefix).st_ino))

    def test_architecture_is_taken_before_any_probe(self):
        make_prefix(self.prefix)
        self.registry()
        self.one(self.responses())
        self.assertEqual(self.runner.calls[0][0], "/usr/bin/lipo")
        port_calls = [c for c in self.runner.calls if os.path.join(self.prefix, "bin", "port") in c]
        self.assertEqual(port_calls, [("/usr/bin/arch", "-arm64", os.path.join(self.prefix, "bin", "port"),
                                       "-N", "version")])

    def test_missing_binary_comes_first(self):
        make_prefix(self.prefix, binary=False, os_major="22")
        self.registry(ports=[port(1, "wget", "1.25.0")])
        inst = self.one(self.responses())
        self.assertEqual((inst.usability, inst.binary, inst.drivable), (Usability.MISSING_BINARY, None, False))
        self.assertTrue(inst.inventory_known)            # the backup still runs: the cannot-run finding sees the rows
        self.assertFalse([c for c in self.runner.calls if "version" in c])

    def test_autoconf_mismatch_beats_missing_registry(self):
        make_prefix(self.prefix, version="2.8.1", os_major="22")
        error = "Error: Current platform \"darwin 25\" does not match expected platform \"darwin 22\"\n"
        inst = self.one(self.responses(version=r.FakeResponse(exit=1, stderr=error)))
        self.assertEqual(inst.usability, Usability.PLATFORM_MISMATCH)
        self.assertIn("darwin 22", inst.usability_detail)
        self.assertEqual(inst.features, ())
        self.assertTrue(inst.inventory_known)            # no registry, nothing installed: known empty

    def test_platform_mismatch_by_stderr(self):
        make_prefix(self.prefix, os_major=None)
        self.registry()
        error = "Warning: MacPorts base should be rebuilt for Apple Silicon\n"
        inst = self.one(self.responses(version=r.FakeResponse(exit=0, stderr=error)))
        self.assertEqual(inst.usability, Usability.PLATFORM_MISMATCH)
        self.assertEqual(inst.usability_detail, error.strip())

    def test_intel_base_on_an_arm64_host(self):
        make_prefix(self.prefix, version="2.9.3")
        self.registry()
        inst = self.one(self.responses(lipo="x86_64\n", arch="-x86_64"))
        self.assertEqual((inst.arch, inst.usability), ("x86_64", Usability.PLATFORM_MISMATCH))

    def test_universal_base_on_intel_runs_without_arch(self):
        make_prefix(self.prefix)
        self.registry()
        inst = self.one(self.responses(arch=None), host_arch="x86_64")
        self.assertEqual((inst.arch, inst.usability), ("x86_64", Usability.USABLE))

    def test_no_registry_with_a_base_only_prefix_is_known_empty(self):
        make_prefix(self.prefix)
        for name in ("portindex", "daemondo"):
            self.write(os.path.join(self.prefix, "bin", name))
        os.symlink("port", os.path.join(self.prefix, "bin", "portf"))
        self.write(os.path.join(self.prefix, "lib", ".turd_MacPorts"))
        os.makedirs(os.path.join(self.prefix, "lib", "pkgconfig"))
        responses = self.responses(version=r.FakeResponse(exit=1, stderr="sqlite error: unable to open database\n"))
        responses[("/usr/sbin/pkgutil", "--files", "org.macports.MacPorts")] = r.FakeResponse(
            stdout="opt/local/lib/.turd_MacPorts\n".replace("opt/local", self.prefix.lstrip("/")))
        inst = self.one(responses)
        self.assertEqual((inst.usability, inst.inventory_known, inst.inventory_error),
                         (Usability.NO_REGISTRY, True, None))
        self.assertIn("registry.db", inst.usability_detail)

    def test_no_registry_with_images_left_is_unknown(self):
        make_prefix(self.prefix)
        self.write(os.path.join(self.prefix, "var", "macports", "software", "wget",
                                "wget-1.25.0_0.darwin_25.arm64.tbz2"))
        inst = self.one(self.responses(version=r.FakeResponse(exit=1)))
        self.assertEqual((inst.usability, inst.inventory_known), (Usability.NO_REGISTRY, False))
        self.assertTrue(inst.inventory_error.startswith("RegistryMissing: "))

    def test_no_registry_with_a_foreign_file_in_bin_is_unknown(self):
        make_prefix(self.prefix)
        self.write(os.path.join(self.prefix, "bin", "wget"))
        inst = self.one(self.responses(version=r.FakeResponse(exit=1)))
        self.assertEqual((inst.usability, inst.inventory_known), (Usability.NO_REGISTRY, False))

    def test_readonly_registry(self):
        make_prefix(self.prefix)
        self.registry()
        error = "sqlite error: attempt to write a readonly database (8) while executing query\n"
        inst = self.one(self.responses(version=r.FakeResponse(exit=1, stderr=error)))
        self.assertEqual(inst.usability, Usability.READONLY_REGISTRY)
        self.assertTrue(inst.inventory_known)

    def test_other_failure_cannot_run(self):
        make_prefix(self.prefix)
        self.registry()
        inst = self.one(self.responses(version=r.FakeResponse(exit=126, stderr="Bad CPU type in executable\n")))
        self.assertEqual((inst.usability, inst.usability_detail), (Usability.CANNOT_RUN, "Bad CPU type in executable"))

    def test_damaged_registry(self):
        make_prefix(self.prefix)
        os.makedirs(os.path.join(self.prefix, "var", "macports", "registry"))
        self.write(os.path.join(self.prefix, "var", "macports", "registry", "registry.db"), "garbage " * 200)
        inst = self.one(self.responses())
        self.assertEqual((inst.usability, inst.drivable, inst.inventory_known),
                         (Usability.DAMAGED_REGISTRY, False, False))
        self.assertTrue(inst.inventory_error.startswith("RegistryDamaged: "))

    def test_damaged_registry_under_mismatch_is_unknown(self):
        make_prefix(self.prefix, version="2.8.1", os_major="22")
        os.makedirs(os.path.join(self.prefix, "var", "macports", "registry"))
        self.write(os.path.join(self.prefix, "var", "macports", "registry", "registry.db"), "garbage " * 200)
        inst = self.one(self.responses(version=r.FakeResponse(exit=1)))
        self.assertEqual((inst.usability, inst.inventory_known), (Usability.PLATFORM_MISMATCH, False))

    def test_busy_registry_usable_but_unknown(self):
        make_prefix(self.prefix)
        self.registry()
        with mock.patch.object(registry, "check_registry",
                               return_value=registry.RegistryCheck("busy", "no progress for 30 s")):
            inst = self.one(self.responses())
        self.assertEqual((inst.usability, inst.inventory_known), (Usability.USABLE, False))
        self.assertTrue(locate.registry_busy(inst))

    def test_unreadable_registry_cannot_run(self):
        make_prefix(self.prefix)
        with mock.patch.object(registry, "check_registry",
                               return_value=registry.RegistryCheck("unreadable", "PermissionError: denied")):
            inst = self.one(self.responses())
        self.assertEqual((inst.usability, inst.inventory_known), (Usability.CANNOT_RUN, False))
        self.assertFalse(locate.registry_busy(inst))

    def test_receipt_version_for_default_prefix_only(self):
        make_prefix(self.prefix, version=None)
        self.registry()
        responses = self.responses()
        responses[("/usr/sbin/pkgutil", "--pkg-info", "org.macports.MacPorts")] = r.FakeResponse(
            stdout="package-id: org.macports.MacPorts\nversion: 0.2.10.4.0.0.0.0.0\n")
        inst = self.one(responses)
        self.assertEqual((inst.version, inst.features), ("2.10.4", ("migrate", "snapshot")))
        other = make_prefix(self.path("opt", "other"), version=None)
        self.registry(other)
        responses.update(self.responses(other))
        found = self.find(responses, path=os.path.join(other, "bin"))
        self.assertEqual([i.version for i in found], ["2.10.4", None])

    def test_two_spellings_of_one_prefix_are_one_instance(self):
        make_prefix(self.prefix)
        self.registry()
        alias = self.path("alias")
        os.symlink(self.prefix, alias)
        self.write("etc/paths", f"{alias}/bin\n/usr/bin\n")
        found = self.find(self.responses(), path=f"{alias}/bin:/usr/bin")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].prefix, self.prefix)
        self.assertEqual(found[0].spellings, (self.prefix, alias))

    def test_other_instances_from_path_and_etc_paths(self):
        second = make_prefix(self.path("opt", "second"))
        third = make_prefix(self.path("opt", "third"))
        for prefix in (second, third):
            self.registry(prefix)
        self.write("etc/paths", f"/usr/bin\n{third}/bin\n{self.path('opt', 'nothing')}/bin/\n")
        responses = dict(self.responses(second))
        responses.update(self.responses(third))
        found = self.find(responses, path=f"/usr/bin:{second}/bin")
        self.assertEqual([i.prefix for i in found], [second, third])
        self.assertTrue(all(i.usability is Usability.USABLE for i in found))

    def test_no_macports(self):
        self.assertEqual(self.find({}), [])


class ChooseTargetTest(TempDirTest):
    """The `ports` target: `--target-prefix` by identity, the Intel refusal, the default and the only instance"""

    def instances(self):
        """Return three MacPorts instances in temporary prefixes: local (arm64), intel (x86_64) and extra (arm64)

        @returns  the instances, in that order
        """
        out = []
        for name, arch in (("local", "arm64"), ("intel", "x86_64"), ("extra", "arm64")):
            prefix = self.path("opt", name)
            os.makedirs(prefix)
            st = os.stat(prefix)
            out.append(make_instance(Manager.PORTS, prefix=prefix, identity=(st.st_dev, st.st_ino), arch=arch))
        return out

    def test_target_prefix_by_identity(self):
        insts = self.instances()
        alias = self.path("alias")
        os.symlink(insts[2].prefix, alias)
        self.assertIs(locate.choose_target(insts, "arm64", alias, default_prefix=insts[0].prefix), insts[2])
        self.assertIsNone(locate.choose_target(insts, "arm64", self.path("none")))

    def test_intel_instance_on_arm64_is_refused(self):
        insts = self.instances()
        with self.assertRaises(locate.TargetRefused):
            locate.choose_target(insts, "arm64", insts[1].prefix)
        self.assertIs(locate.choose_target(insts, "x86_64", insts[1].prefix), insts[1])

    def test_default_prefix_then_the_only_instance(self):
        insts = self.instances()
        self.assertIs(locate.choose_target(insts, "arm64", None, default_prefix=insts[0].prefix), insts[0])
        self.assertIsNone(locate.choose_target(insts[1:], "arm64", None, default_prefix=insts[0].prefix))
        self.assertIs(locate.choose_target(insts[2:], "arm64", None, default_prefix=insts[0].prefix), insts[2])
        brew = make_instance(Manager.BREW, prefix=self.path("opt", "local"))
        self.assertIsNone(locate.choose_target([brew], "arm64", None, default_prefix=self.path("nowhere")))


if __name__ == "__main__":
    unittest.main()

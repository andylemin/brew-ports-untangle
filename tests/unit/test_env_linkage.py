"""Mach-O detection, the linkage scan set and the `otool -l` linkage classes"""

import os
import struct
import sys
import unittest

from brew_ports import model, runner as r
from brew_ports.env import linkage as lk
from tests.unit.helpers import make_package
from tests.unit.test_env_paths import EnvTest, fixture

THIN64 = b"\xcf\xfa\xed\xfe" + b"\x0c\x00\x00\x01" + b"\x00" * 24
THIN32_BE = b"\xfe\xed\xfa\xce" + b"\x00" * 24
FAT = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\x00" * 40
FAT64 = b"\xca\xfe\xba\xbf" + struct.pack(">I", 3) + b"\x00" * 40
JAVA = b"\xca\xfe\xba\xbe" + b"\x00\x00\x00\x34" + b"\x00" * 16     # class file, major version 52


def section(path, refs=(), rpaths=(), arch=None):
    """Format the `otool -l` text of one file as cctools-1040 prints it

    @param path    the file
    @param refs    its load commands, as (command, install name) pairs
    @param rpaths  its `LC_RPATH` entries
    @param arch    the architecture of one slice of a fat file; None for a thin file
    @returns       the text, ending in a newline
    """
    architecture = f" (architecture {arch})" if arch else ""
    lines = [f"{path}{architecture}:"]
    number = 0
    for command, name in refs:
        lines += [f"Load command {number}", f"          cmd {command}", "      cmdsize 56",
                  f"         name {name} (offset 24)", "   time stamp 2 Thu Jan  1 10:00:02 1970",
                  "      current version 1.0.0", "compatibility version 1.0.0"]
        number += 1
    for rpath in rpaths:
        lines += [f"Load command {number}", "          cmd LC_RPATH", "      cmdsize 32",
                  f"         path {rpath} (offset 12)"]
        number += 1
    return "\n".join(lines) + "\n"


class MachOTest(EnvTest):
    """Tests of the Mach-O magic check and the keg walk"""

    def test_magic_bytes(self):
        cases = {"thin64": (THIN64, True), "thin32": (THIN32_BE, True), "fat": (FAT, True), "fat64": (FAT64, True),
                 "swapped": (b"\xce\xfa\xed\xfe" + b"\x00" * 8, True), "java.bin": (JAVA, False),
                 "Main.class": (FAT, False), "text": (b"#!/bin/sh\n", False), "short": (b"\xca\xfe", False),
                 "empty": (b"", False)}
        for name, (data, expected) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(lk.is_macho(self.touch(self.path("m", name), data)), expected)
        self.assertFalse(lk.is_macho(self.path("m", "missing")))

    def test_keg_walk_with_lib_nesting(self):
        keg = self.path("opt", "homebrew", "Cellar", "foo", "1.0")
        expect = [
            self.touch(os.path.join(keg, "Frameworks", "Foo.framework", "Versions", "A", "Foo"), THIN64),
            self.touch(os.path.join(keg, "bin", "tool"), THIN64),
            self.touch(os.path.join(keg, "lib", "a", "b", "c", "libdeep.dylib"), THIN64),
            self.touch(os.path.join(keg, "lib", "libfoo.dylib"), THIN32_BE),
            self.touch(os.path.join(keg, "libexec", "helper"), FAT),
            self.touch(os.path.join(keg, "sbin", "daemon"), FAT64),
        ]
        os.symlink("A", os.path.join(keg, "Frameworks", "Foo.framework", "Versions", "Current"))
        os.symlink("tool", os.path.join(keg, "bin", "link"))
        self.touch(os.path.join(keg, "lib", "Main.class"), FAT)
        self.touch(os.path.join(keg, "lib", "java.bin"), JAVA)
        self.touch(os.path.join(keg, "lib", "pkgconfig", "foo.pc"), b"prefix=/x\n")
        self.touch(os.path.join(keg, "share", "foo", "plugin.dylib"), THIN64)      # not walked
        self.touch(os.path.join(keg, "bin", "deep", "nested"), THIN64)             # bin is not recursive
        self.assertEqual(lk.keg_binaries(keg), sorted(expect))
        self.assertEqual(lk.keg_binaries(self.path("no-such-keg")), [])


class ScanSetTest(unittest.TestCase):
    """Tests of the linkage scan set and the package keys"""

    def test_default_deep_and_dependents(self):
        bottled = make_package("jq", built_locally=False, receipt_ok=True)
        built = make_package("babashka", built_locally=True)
        no_receipt = make_package("perl", built_locally=None, receipt_ok=False)
        unknown = make_package("dbus", built_locally=None, receipt_ok=True)
        cask = make_package("firefox", kind="cask", built_locally=None)
        active = make_package("gsed", kind="port", prefix="/opt/local", active=True)
        inactive = make_package("gsed", kind="port", prefix="/opt/local", active=False, version="4.8_0")
        dependent = make_package("curl", built_locally=False, deps=["openssl@3"])
        packages = [bottled, built, no_receipt, unknown, cask, active, inactive, dependent]

        def names(pkgs):
            return [(p.kind, p.name, p.version) for p in pkgs]
        self.assertEqual(names(lk.scan_set(packages, False)),
                         names([built, no_receipt, unknown, active]))
        self.assertEqual(names(lk.scan_set(packages, True)),
                         names([bottled, built, no_receipt, unknown, active, dependent]))
        self.assertEqual(names(lk.scan_set(packages, False, dependents_of=["openssl@3"])),
                         names([built, no_receipt, unknown, active, dependent]))

    def test_keys_and_binaries_by_package(self):
        port = make_package("gsed", kind="port", prefix="/opt/local", binaries=["/opt/local/bin/gsed"])
        self.assertEqual(lk.package_key(port), "/opt/local|port|gsed")
        self.assertEqual(lk.binaries_by_package([port]), {"/opt/local|port|gsed": ["/opt/local/bin/gsed"]})


class KegBinariesByPackageTest(EnvTest):
    """Tests of the keg walk for a formula whose inventory lists no binaries"""

    def test_a_formula_without_binaries_gets_its_keg_walked(self):
        brew = self.instance()
        tool = self.touch(os.path.join(brew.prefix, "Cellar", "foo", "1.2_1", "bin", "foo"), THIN64)
        pkg = make_package("foo", prefix=brew.prefix, version="1.2_1")
        self.assertEqual(lk.formula_keg(pkg), os.path.join(brew.prefix, "Cellar", "foo", "1.2_1"))
        self.assertEqual(lk.binaries_by_package([pkg]), {f"{brew.prefix}|formula|foo": [tool]})


class SharedCacheTest(unittest.TestCase):
    """Tests of the dyld shared cache lookup"""

    @unittest.skipIf(sys.platform == "darwin", "macOS has the dyld shared cache")
    def test_off_macos_the_answer_is_false(self):
        self.assertFalse(lk.shared_cache_contains("/usr/lib/libSystem.B.dylib"))

    @unittest.skipUnless(sys.platform == "darwin", "needs the dyld shared cache")
    def test_libsystem_is_in_the_cache(self):
        self.assertTrue(lk.shared_cache_contains("/usr/lib/libSystem.B.dylib"))
        self.assertFalse(lk.shared_cache_contains("/usr/lib/libbrew-ports-made-up.dylib"))

    def test_a_failing_lookup_is_false(self):
        saved = dict(lk._CACHE_LOOKUP)

        def restore():
            lk._CACHE_LOOKUP.clear()
            lk._CACHE_LOOKUP.update(saved)
        self.addCleanup(restore)

        def boom(path):
            raise OSError("no cache")
        lk._CACHE_LOOKUP["fn"] = boom
        self.assertFalse(lk.shared_cache_contains("/usr/lib/libz.1.dylib"))


class ParseTest(unittest.TestCase):
    """Tests of the `otool -l` parser"""

    def test_sections_and_load_commands(self):
        text = (section("/a/bin/x", [("LC_LOAD_DYLIB", "/a/lib/liby.dylib"), ("LC_ID_DYLIB", "@rpath/libx.dylib"),
                                     ("LC_LOAD_DYLINKER", "/usr/lib/dyld")], rpaths=["@loader_path/../lib"])
                + section("/a/bin/fat", [("LC_LOAD_WEAK_DYLIB", "/w.dylib")], arch="x86_64")
                + section("/a/bin/fat", [("LC_LOAD_DYLIB", "/z.dylib")], arch="arm64")
                + "/a/share/doc: is not an object file\n"
                + section("/a/lib/libq.a(q.o)", [("LC_LOAD_DYLIB", "/ignored.dylib")]))
        sections, errors = lk.parse_otool(text, ["/a/bin/x", "/a/bin/fat", "/a/share/doc", "/a/lib/libq.a"])
        x = sections["/a/bin/x"][0]
        self.assertEqual(x.references, [("LC_LOAD_DYLIB", "/a/lib/liby.dylib")])
        self.assertEqual(x.rpaths, ["@loader_path/../lib"])
        self.assertEqual([(s.arch, s.references) for s in sections["/a/bin/fat"]],
                         [("x86_64", [("LC_LOAD_WEAK_DYLIB", "/w.dylib")]), ("arm64", [("LC_LOAD_DYLIB", "/z.dylib")])])
        self.assertEqual(errors, {"/a/share/doc": "not an object file"})
        self.assertNotIn("/a/lib/libq.a", sections)


class ClassesTest(EnvTest):
    """Tests of the linkage classes, the `otool` batches and their failures"""

    def setUp(self):
        super().setUp()
        self.brew = self.instance(model.Manager.BREW, "opt/homebrew")
        self.ports = self.instance(model.Manager.PORTS, "opt/local")
        self.ulocal = self.path("usr", "local")
        self.sys_root = self.path("usr", "lib")
        self.elsewhere = self.path("opt", "X11")
        keg = os.path.join(self.brew.prefix, "Cellar", "foo", "1.0")
        self.tool = self.touch(os.path.join(keg, "bin", "foo"), THIN64)
        self.lib = self.touch(os.path.join(keg, "lib", "libfoo.1.dylib"), THIN64)
        for path in (os.path.join(keg, "lib", "libbaz.2.dylib"), os.path.join(keg, "lib", "libqux.dylib"),
                     os.path.join(self.brew.prefix, "opt", "bar", "lib", "libbar.1.dylib"),
                     os.path.join(self.ports.prefix, "lib", "libz.1.dylib"),
                     os.path.join(self.ulocal, "lib", "libstray.dylib"),
                     os.path.join(self.elsewhere, "lib", "libX11.6.dylib")):
            self.touch(path, THIN64)
        os.makedirs(self.sys_root)
        self.fat = self.touch(os.path.join(self.ports.prefix, "bin", "fatty"), FAT)
        self.txt = self.touch(os.path.join(self.ports.prefix, "share", "readme"), b"text\n")
        self.text = fixture("otool-l-classes.txt", FOO=self.tool, LIB=self.lib, FAT=self.fat, TXT=self.txt,
                            ARCHIVE=os.path.join(self.ports.prefix, "lib", "libarchive.a"), BREW=self.brew.prefix,
                            PORTS=self.ports.prefix, USRLOCAL=self.ulocal, SYS=self.sys_root,
                            ELSEWHERE=self.elsewhere)

    def cache(self, path):
        """Answer the shared cache lookup, which holds the test's `libSystem.B.dylib` alone

        @param path  the library
        @returns     True for that library only
        """
        return path == os.path.join(self.sys_root, "libSystem.B.dylib")

    def scan(self, responses, by_package, instances=None):
        """Run the linkage scan on a fake runner, with the test's system root and `/usr/local`

        @param responses   the canned `otool` responses, by argv
        @param by_package  the binaries by package key
        @param instances   the instances; None for the Homebrew and the MacPorts one
        @returns           the report and the fake runner
        """
        fake = self.runner(responses)
        report = lk.scan(fake, by_package, instances or [self.brew, self.ports], in_shared_cache=self.cache,
                         system_roots=(self.sys_root,), usr_local=self.ulocal)
        return report, fake

    def test_every_class_in_its_order(self):
        brew_key, port_key = f"{self.brew.prefix}|formula|foo", f"{self.ports.prefix}|port|fatty"
        argv = (lk.OTOOL, "-l", self.tool, self.lib, self.fat, self.txt)
        report, fake = self.scan({argv: r.FakeResponse(stdout=self.text)},
                                 {brew_key: [self.tool, self.lib], port_key: [self.fat, self.txt]})
        self.assertEqual(fake.calls, [argv])
        tool = report["binaries"][self.tool]
        self.assertEqual(tool["instance_prefix"], self.brew.prefix)
        self.assertEqual([(ref["command"], ref["class"]) for ref in tool["references"]], [
            ("LC_LOAD_DYLIB", "own"), ("LC_LOAD_DYLIB", "other"), ("LC_LOAD_DYLIB", "usrlocal"),
            ("LC_LOAD_DYLIB", "system"), ("LC_LOAD_DYLIB", "missing"), ("LC_LOAD_WEAK_DYLIB", "weak"),
            ("LC_LOAD_DYLIB", "own"), ("LC_LOAD_DYLIB", "unresolved"), ("LC_REEXPORT_DYLIB", "own"),
            ("LC_LOAD_UPWARD_DYLIB", "variable"), ("LC_LOAD_DYLIB", "external")])
        rpath_ref = tool["references"][6]
        self.assertEqual(rpath_ref["resolved"],
                         os.path.realpath(os.path.join(os.path.dirname(self.lib), "libbaz.2.dylib")))
        self.assertIsNone(tool["references"][7]["resolved"])
        self.assertEqual([ref["class"] for ref in report["binaries"][self.lib]["references"]], ["system"])
        fat = report["binaries"][self.fat]
        self.assertEqual(fat["archs"], ["x86_64", "arm64"])
        self.assertEqual([(ref["arch"], ref["class"]) for ref in fat["references"]],
                         [("x86_64", "usrlocal"), ("arm64", "own")])
        self.assertEqual(report["binaries"][self.txt]["error"], "not an object file")
        self.assertEqual(report["packages"][brew_key]["broken"], [self.tool])
        self.assertEqual(report["packages"][brew_key]["classes"],
                         {"variable": 1, "unresolved": 1, "missing": 1, "weak": 1, "own": 3, "other": 1,
                          "usrlocal": 1, "system": 2, "external": 1})
        self.assertEqual(report["packages"][port_key], {"binaries": 2, "classes": {"own": 1, "usrlocal": 1},
                                                        "broken": [self.fat]})
        self.assertEqual(report["errors"], [])
        missing = lk.references(report, ["missing"])
        self.assertEqual([(key, path, ref["name"]) for key, path, ref in missing],
                         [(brew_key, self.tool, os.path.join(self.sys_root, "libmadeup.dylib"))])

    def test_the_instance_at_usr_local_owns_its_roots_only(self):
        ul = self.usr_local_instance()
        ul_bin = self.touch(os.path.join(ul.prefix, "Cellar", "foo", "1.0", "bin", "foo"), THIN64)
        libbar = self.touch(os.path.join(ul.prefix, "opt", "bar", "lib", "libbar.dylib"), THIN64)
        stray = os.path.join(ul.prefix, "lib", "libstray.dylib")
        port_bin = self.touch(os.path.join(self.ports.prefix, "bin", "x"), THIN64)
        text = (section(ul_bin, [("LC_LOAD_DYLIB", stray), ("LC_LOAD_DYLIB", libbar)])
                + section(port_bin, [("LC_LOAD_DYLIB", stray), ("LC_LOAD_DYLIB", libbar)]))
        fake = self.runner({(lk.OTOOL, "-l", ul_bin, port_bin): r.FakeResponse(stdout=text)})
        report = lk.scan(fake, {"u": [ul_bin], "p": [port_bin]}, [ul, self.ports], in_shared_cache=self.cache,
                         system_roots=(self.sys_root,), usr_local=ul.prefix)
        self.assertEqual([x["class"] for x in report["binaries"][ul_bin]["references"]], ["external", "own"])
        self.assertEqual([x["class"] for x in report["binaries"][port_bin]["references"]], ["usrlocal", "other"])

    def usr_local_instance(self):
        """Return a Homebrew instance at `/usr/local` with a stray library outside its roots

        @returns  the instance
        """
        ul = self.usr_local()
        self.touch(os.path.join(ul.prefix, "lib", "libstray.dylib"), THIN64)
        return ul

    def test_batches_of_fifty(self):
        files = [os.path.join(self.brew.prefix, "Cellar", "big", "1.0", "lib", f"lib{n:03d}.dylib") for n in range(120)]

        def respond(key):
            return r.FakeResponse(stdout="".join(section(p, [("LC_LOAD_DYLIB", "@executable_path/x")])
                                                 for p in key[2:]))
        fake = self.runner(default=respond)
        report = lk.scan(fake, {"big": files}, [self.brew], in_shared_cache=self.cache,
                         system_roots=(self.sys_root,), usr_local=self.ulocal)
        self.assertEqual([len(call) - 2 for call in fake.calls], [50, 50, 20])
        self.assertEqual(len(report["binaries"]), 120)
        self.assertEqual(report["classes"], {"variable": 120})
        self.assertTrue(all(item["error"] is None for item in report["binaries"].values()))

    def test_a_failed_batch_is_still_parsed(self):
        gone = os.path.join(self.brew.prefix, "Cellar", "foo", "1.0", "bin", "gone")
        argv = (lk.OTOOL, "-l", self.tool, gone)
        response = r.FakeResponse(exit=1, stdout=section(self.tool, [("LC_LOAD_DYLIB", os.path.join(
            self.ports.prefix, "lib", "libz.1.dylib"))]), stderr=f"error: can't open file: {gone}\n")
        report, _ = self.scan({argv: response}, {"k": [self.tool, gone]})
        self.assertEqual([x["class"] for x in report["binaries"][self.tool]["references"]], ["other"])
        self.assertEqual(report["binaries"][gone]["error"], "no otool output")
        self.assertEqual(len(report["errors"]), 1)
        self.assertIn("exited 1", report["errors"][0])

    def test_a_binary_shared_by_two_packages_is_scanned_once(self):
        argv = (lk.OTOOL, "-l", self.tool)
        report, fake = self.scan({argv: r.FakeResponse(stdout=section(self.tool))},
                                 {"a": [self.tool], "b": [self.tool]})
        self.assertEqual(fake.calls, [argv])
        self.assertEqual(report["binaries"][self.tool]["package"], "a")
        self.assertEqual(report["packages"]["b"]["broken"], [])


if __name__ == "__main__":
    unittest.main()

"""The MacPorts inventory: the outdated rule, packages from the registry, select groups and the `scan` text"""

import json
import os
import unittest
from typing import Any

from brew_ports import runner as r
from brew_ports.macports import inventory, registry
from brew_ports.macports.portindex import PortEntry
from brew_ports.model import Manager
from tests.unit.fixtures.macports.builders import (FakePortIndex, fake_runner, make_prefix, make_registry, port,
                                                   read_fixture)
from tests.unit.helpers import TempDirTest, make_instance


def row(**kw):
    """Return an installed, requested curl row of `ports`, with `kw` overriding its columns

    @param kw  the columns to override
    @returns   the registry row
    """
    base: dict[str, Any] = {
        "id": 1, "name": "curl", "version": "8.9.1", "revision": 0, "epoch": 0, "variants": "", "state": "installed",
        "requested": True, "os_platform": "darwin", "os_major": "25", "archs": "arm64", "location": None, "date": None,
        "requested_variants": "", "cxx_stdlib": "libc++", "cxx_stdlib_overridden": 0}
    base.update(kw)
    return registry.PortRow(**base)


class OutdatedRuleTest(unittest.TestCase):
    """The `port outdated` rule: version, revision, epoch and the C++ standard library"""

    def outdated(self, *, version="8.9.1", revision=0, epoch=0, latest="8.9.1", latest_revision=0, latest_epoch=0,
                 cxx="libc++", overridden=0, configured="libc++"):
        """Return whether `is_outdated` reports an installed curl as outdated against its PortIndex entry

        @param version          the installed version
        @param revision         the installed revision
        @param epoch            the installed epoch
        @param latest           the PortIndex version
        @param latest_revision  the PortIndex revision
        @param latest_epoch     the PortIndex epoch
        @param cxx              the C++ standard library the installed port was built against
        @param overridden       the row's `cxx_stdlib_overridden`
        @param configured       the configured C++ standard library
        @returns                the verdict
        """
        installed = row(version=version, revision=revision, epoch=epoch, cxx_stdlib=cxx,
                        cxx_stdlib_overridden=overridden)
        entry = PortEntry(name="curl", version=latest, revision=latest_revision, epoch=latest_epoch)
        return inventory.is_outdated(installed, entry, configured)

    def test_version_then_revision(self):
        self.assertTrue(self.outdated(latest="8.10.1"))
        self.assertFalse(self.outdated(version="8.10.1", latest="8.9.1"))
        self.assertFalse(self.outdated())
        self.assertTrue(self.outdated(latest_revision=1))
        self.assertFalse(self.outdated(revision=2, latest_revision=1))

    def test_epoch_decides_only_when_the_version_strings_differ(self):
        self.assertTrue(self.outdated(version="1.6.44", latest="1.6.40", latest_epoch=1))
        self.assertFalse(self.outdated(version="2.0", epoch=1, latest="3.0", latest_epoch=0))
        self.assertFalse(self.outdated(version="3.30.5", latest="3.30.5", latest_epoch=1))
        self.assertTrue(self.outdated(version="3.30.5", latest="3.30.5", latest_epoch=1, latest_revision=1))

    def test_cxx_stdlib_at_an_equal_version(self):
        self.assertTrue(self.outdated(cxx="libstdc++"))
        self.assertFalse(self.outdated(cxx="libstdc++", overridden=1))
        self.assertFalse(self.outdated(cxx="libstdc++", overridden=None))
        self.assertFalse(self.outdated(cxx="none"))
        self.assertFalse(self.outdated(cxx=None, overridden=None))
        self.assertTrue(self.outdated(cxx="libc++", configured="libstdc++"))
        self.assertFalse(self.outdated(latest="8.8.0", cxx="libstdc++"))

    def test_configured_cxx_stdlib(self):
        self.assertEqual(inventory.configured_cxx_stdlib({}, ("darwin", 25)), "libc++")
        self.assertEqual(inventory.configured_cxx_stdlib({}, ("darwin", 9)), "libstdc++")
        self.assertEqual(inventory.configured_cxx_stdlib({}, ("linux", 6)), "")
        self.assertEqual(inventory.configured_cxx_stdlib({"cxx_stdlib": "libstdc++"}, ("darwin", 25)), "libstdc++")


class InventoryTest(TempDirTest):
    """The inventory of a prefix with fourteen registry rows, a select group and a PortIndex"""

    def setUp(self):
        super().setUp()
        self.runner = fake_runner(self.tmp)            # replaced by the runner of each run_inventory()
        self.prefix = make_prefix(self.path("opt", "local"))
        self.portdb = os.path.join(self.prefix, "var", "macports")
        self.home = self.path("home")
        p = self.prefix

        def image(name, spec):
            return self.write(os.path.join(self.portdb, "software", name, f"{name}-{spec}.darwin_25.arm64.tbz2"))

        ports = [
            port(1, "zlib", "1.3.1", requested=0, location=image("zlib", "1.3.1_0")),
            port(2, "curl", "8.9.1", location=image("curl", "8.9.1_0")),
            port(3, "curl", "8.8.0", state="imaged", location=image("curl", "8.8.0_0")),
            port(4, "gettext", "0.22.5", requested=0, location=image("gettext", "0.22.5_0")),
            port(5, "libiconv", "1.17", state="imaged", requested=0, location=image("libiconv", "1.17_0")),
            port(6, "vim", "9.1.0", variants="+huge", requested_variants="+huge-x11",
                 location=os.path.join(self.portdb, "software", "vim", "vim-9.1.0_0+huge.darwin_25.arm64.tbz2")),
            port(7, "python312", "3.12.7", location=image("python312", "3.12.7_0")),
            port(8, "dbus", "1.14.10", requested=0, location=image("dbus", "1.14.10_0")),
            port(9, "cmake", "3.30.5", location=image("cmake", "3.30.5_0")),
            port(10, "libpng", "1.6.44", location=image("libpng", "1.6.44_0")),
            port(11, "boost181", "1.81.0", cxx_stdlib="libstdc++", location=image("boost181", "1.81.0_0")),
            port(12, "qt5", "5.15.16", cxx_stdlib="libstdc++", cxx_stdlib_overridden=1,
                 location=image("qt5", "5.15.16_0")),
            port(13, "gnome-themes-standard", "3.27.90", location=image("gnome-themes-standard", "3.27.90_0")),
            port(14, "obsolete-tool", "1.0", os_platform="any", os_major="any",
                 location=image("obsolete-tool", "1.0_0")),
        ]
        plist = "/Library/LaunchDaemons/org.freedesktop.dbus-system.plist"
        target = p + "/etc/LaunchDaemons/org.freedesktop.dbus-system/org.freedesktop.dbus-system.plist"
        files = [
            (6, p + "/bin/vim", p + "/bin/vim", 1, 1), (6, p + "/bin/vimdiff", p + "/bin/vimdiff", 1, 0),
            (6, p + "/share/vim/vim91/doc/help.txt", p + "/share/vim/vim91/doc/help.txt", 1, 0),
            (2, p + "/bin/curl", p + "/bin/curl", 1, 1),
            (2, p + "/lib/libcurl.4.dylib", p + "/lib/libcurl.4.dylib", 1, 1),
            (3, p + "/bin/curl", None, 0, 1),
            (7, p + "/bin/python3.12", p + "/bin/python3.12", 1, 1),
            (7, p + "/etc/select/python3/python312", p + "/etc/select/python3/python312", 1, 0),
            (8, plist, plist, 1, 0), (8, target, target, 1, 0),
            (8, p + "/bin/dbus-daemon", p + "/bin/dbus-daemon", 1, 1),
        ]
        deps = [(2, "zlib"), (3, "zlib"), (4, "LibIconv"), (6, "ncurses"), (7, "zlib")]
        make_registry(self.portdb, schema="1.215", ports=ports, files=files, deps=deps)
        select = os.path.join(p, "etc", "select", "python3")
        self.write(os.path.join(select, "base"), "bin/python3\n")
        self.write(os.path.join(select, "none"), "-\n")
        self.write(os.path.join(select, "python312"),
                   "${frameworks_dir}/Python.framework/Versions/3.12/bin/python3.12\n")
        os.symlink("python312", os.path.join(select, "current"))
        self.index = FakePortIndex([
            PortEntry("zlib", "1.3.1"), PortEntry("curl", "8.10.1", homepage="https://curl.se/",
                                                  description="Tool for transferring data with URL syntax"),
            PortEntry("gettext", "0.22.5"), PortEntry("libiconv", "1.17"), PortEntry("vim", "9.1.0"),
            PortEntry("python312", "3.12.7"), PortEntry("dbus", "1.14.10"), PortEntry("cmake", "3.30.5", epoch=1),
            PortEntry("libpng", "1.6.40", epoch=1), PortEntry("boost181", "1.81.0"), PortEntry("qt5", "5.15.16"),
            PortEntry("gnome-themes-standard", "3.28", replaced_by="adwaita-icon-theme")])

    def instance(self, **kw):
        """Return the MacPorts instance of the test prefix, with `kw` overriding its fields

        @param kw  the `Instance` fields to override
        @returns   the instance
        """
        st = os.stat(self.prefix)
        base: dict[str, Any] = {"prefix": self.prefix, "identity": (st.st_dev, st.st_ino), "portdbpath": self.portdb,
                                "arch": "arm64", "binary": os.path.join(self.prefix, "bin", "port")}
        base.update(kw)
        return make_instance(Manager.PORTS, **base)

    def run_inventory(self, inst=None, index="default", responses=None):
        """Read the inventory of an instance with a fake runner, closed when the test ends

        @param inst       the instance; None for the test prefix's
        @param index      the PortIndex; `default` for the test's, None for none
        @param responses  the fake runner's responses; None answers `port select --summary` from the fixture
        @returns          the inventory
        """
        inst = inst or self.instance()
        summary = ("/usr/bin/arch", "-arm64", os.path.join(self.prefix, "bin", "port"), "-N", "select", "--summary")
        fake = fake_runner(self.tmp, responses if responses is not None else
                           {summary: r.FakeResponse(stdout=read_fixture("port-select-summary.txt"))}, home=self.home)
        self.runner = fake
        inv = inventory.inventory(fake, inst, self.index if index == "default" else index, platform=("darwin", 25))
        self.addCleanup(inv.close)
        return inv

    def pkg(self, inv, name, active=True):
        """Return the package of a port in one state

        @param inv     the inventory
        @param name    the port's name
        @param active  whether the package is the active row or an inactive one
        @returns       the first package that matches
        """
        return next(p for p in inv.packages if p.name == name and p.active == active)

    def test_every_row_is_a_package(self):
        inv = self.run_inventory()
        self.assertTrue(inv.known)
        self.assertEqual(len(inv.packages), 14)
        self.assertEqual([p.name for p in inv.packages], [row.name for row in inv.rows])
        self.assertEqual(inv.schema_version, "1.215")
        self.assertEqual(inv.registry_prefix, self.prefix)
        curl = [p for p in inv.packages if p.name == "curl"]
        self.assertEqual([(p.spec_args, p.active) for p in curl],
                         [(["curl", "@8.8.0_0"], False), (["curl", "@8.9.1_0"], True)])
        for p in inv.packages:
            self.assertEqual((p.kind, p.instance_prefix, p.linked), ("port", self.prefix, None))

    def test_spec_args_variants_and_image(self):
        vim = self.pkg(self.run_inventory(), "vim")
        self.assertEqual(vim.spec_args, ["vim", "@9.1.0_0+huge"])
        self.assertEqual(vim.version, "9.1.0_0+huge")
        self.assertEqual(vim.requested_variants, ["+huge", "-x11"])
        self.assertTrue(vim.built_locally)
        self.assertFalse(vim.receipt_ok)
        self.assertTrue(self.pkg(self.run_inventory(), "curl").receipt_ok)
        self.assertEqual(vim.built_on_os, "darwin 25")
        self.assertEqual(vim.archs, ["arm64"])

    def test_outdated_rule(self):
        inv = self.run_inventory()
        outdated = {p.name: p.outdated for p in inv.packages if p.active}
        self.assertEqual({n for n, o in outdated.items() if o}, {"curl", "libpng", "boost181", "gnome-themes-standard"})
        self.assertFalse(self.pkg(inv, "curl", active=False).outdated)

    def test_catalogue_fields(self):
        inv = self.run_inventory()
        curl = self.pkg(inv, "curl")
        self.assertEqual((curl.homepage, curl.description),
                         ("https://curl.se/", "Tool for transferring data with URL syntax"))
        self.assertEqual(curl.origin, self.index.source)
        self.assertEqual(self.pkg(inv, "gnome-themes-standard").renamed_to, "adwaita-icon-theme")
        obsolete = self.pkg(inv, "obsolete-tool")
        self.assertEqual((obsolete.catalogue_present, obsolete.origin, obsolete.outdated), (False, "", False))
        self.assertEqual(obsolete.built_on_os, "any any")
        self.assertEqual(inv.portindex_path, self.index.path)

    def test_without_a_portindex(self):
        inv = self.run_inventory(index=None)
        self.assertTrue(all(p.catalogue_present and not p.outdated for p in inv.packages))
        self.assertIsNone(inv.portindex_path)

    def test_dependencies_and_dependents(self):
        inv = self.run_inventory()
        self.assertEqual(self.pkg(inv, "zlib").dependents, ["curl", "python312"])
        self.assertEqual(self.pkg(inv, "libiconv", active=False).dependents, ["gettext"])
        self.assertEqual(self.pkg(inv, "gettext").deps, ["LibIconv"])
        self.assertEqual(self.pkg(inv, "curl").deps, ["zlib"])
        self.assertEqual([p.name for p in inv.leaves()], ["dbus", "gettext"])
        self.assertEqual([p.name for p in inv.rleaves()], ["dbus", "gettext", "libiconv"])

    def test_executables_and_select_groups(self):
        inv = self.run_inventory()
        self.assertEqual(self.pkg(inv, "vim").executables, ["vim", "vimdiff"])
        self.assertEqual(self.pkg(inv, "curl", active=False).executables, ["curl"])
        self.assertEqual(self.pkg(inv, "dbus").executables, ["dbus-daemon"])
        self.assertEqual(self.pkg(inv, "python312").select_groups, ["python3"])
        self.assertEqual(self.pkg(inv, "vim").select_groups, [])
        group = inv.select_groups[0]
        self.assertEqual((group.name, group.current, group.options, group.base),
                         ("python3", "python312", ["none", "python312"], ["bin/python3"]))
        self.assertEqual(inv.select_summary, ["python3  python312  none python311 python312",
                                              "gcc      none       mp-gcc14 none"])
        self.assertEqual(inventory.parse_select_summary(inv.select_summary)[0],
                         ("python3", "python312", ["none", "python311", "python312"]))

    def test_select_summary_empty_and_undrivable(self):
        summary = ("/usr/bin/arch", "-arm64", os.path.join(self.prefix, "bin", "port"), "-N", "select", "--summary")
        inv = self.run_inventory(responses={summary: r.FakeResponse(
            exit=1, stderr="No ports with the select option were found.\n")})
        self.assertEqual(inv.select_summary, [])
        inv = self.run_inventory(self.instance(drivable=False), responses={})
        self.assertIsNone(inv.select_summary)
        self.assertNotIn(summary, self.runner.calls)

    def test_files_on_demand_and_ownership(self):
        inv = self.run_inventory()
        vim = self.pkg(inv, "vim")
        self.assertEqual(len(inv.files(vim)), 3)
        self.assertEqual(inv.binaries(vim), [self.prefix + "/bin/vim"])
        self.assertEqual(inv.binaries(self.pkg(inv, "curl", active=False)), [])
        self.assertEqual(inv.owner_of("/Library/LaunchDaemons/org.freedesktop.dbus-system.plist"), "dbus")
        self.assertEqual(inv.owner_of(self.prefix + "/etc/LaunchDaemons/org.freedesktop.dbus-system/"
                                      "org.freedesktop.dbus-system.plist"), "dbus")
        self.assertEqual(inv.owner_of("/System/Volumes/Data" + self.prefix + "/bin/vim"), "vim")
        self.assertIsNone(inv.owner_of("/Library/LaunchDaemons/com.example.other.plist"))
        self.assertTrue(inv.is_registered(self.prefix + "/lib/libcurl.4.dylib"))
        self.assertFalse(inv.is_registered(self.prefix + "/lib/stray.dylib"))
        self.assertTrue(inv.is_base_file(self.prefix + "/bin/port"))
        self.assertFalse(inv.is_base_file(self.prefix + "/bin/vim"))
        self.assertIs(inv.row_for(vim), inv.rows[inv.packages.index(vim)])

    def test_image_archives_facts_and_text(self):
        inv = self.run_inventory()
        self.assertIn("curl", inv.image_archives)
        self.assertNotIn("vim", inv.image_archives)
        facts = json.loads(json.dumps(inv.facts()))
        self.assertEqual(facts["schema_version"], "1.215")
        self.assertEqual(facts["select_groups"][0]["name"], "python3")
        self.assertEqual((facts["autoconf"]["os_platform"], facts["autoconf"]["os_major"]), ("darwin", "25"))
        text = "\n".join(inventory.render_lines(inv))
        self.assertIn(f"MacPorts 2.12.7 at {self.prefix} (usable), built for darwin 25", text)
        self.assertIn("image missing", text)

    def test_close_removes_the_copy(self):
        inv = self.run_inventory()
        directory = inv._registry._tmp.name
        self.assertTrue(os.path.isdir(directory))
        inv.close()
        self.assertFalse(os.path.exists(directory))
        self.assertEqual(inv.files(inv.packages[0]), [])
        self.assertIsNone(inv.owner_of("/Library/LaunchDaemons/org.freedesktop.dbus-system.plist"))

    def test_unknown_inventory_reports_the_images(self):
        inst = self.instance(inventory_known=False, inventory_error="RegistryDamaged: malformed", drivable=False)
        inv = self.run_inventory(inst, responses={})
        self.assertEqual((inv.known, inv.packages, inv.rows, inv.error), (False, [], [], "RegistryDamaged: malformed"))
        self.assertIn("curl", inv.image_archives)
        self.assertIn("ports unknown: RegistryDamaged: malformed", "\n".join(inventory.render_lines(inv)))

    def test_failed_backup_leaves_inventory_unknown(self):
        with open(os.path.join(self.portdb, "registry", "registry.db"), "wb") as fh:
            fh.write(b"garbage" * 1000)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(os.path.join(self.portdb, "registry", "registry.db" + suffix)):
                os.unlink(os.path.join(self.portdb, "registry", "registry.db" + suffix))
        inst = self.instance()
        inv = self.run_inventory(inst)
        self.assertFalse(inv.known)
        self.assertEqual(inv.packages, [])
        self.assertFalse(inst.inventory_known)
        self.assertTrue(inst.inventory_error.startswith("RegistryDamaged: "))

    def test_known_empty_prefix_without_a_registry(self):
        os.unlink(os.path.join(self.portdb, "registry", "registry.db"))
        inv = self.run_inventory()
        self.assertEqual((inv.known, inv.packages, inv.schema_version), (True, [], None))


class OldSchemaInventoryTest(TempDirTest):
    """An inventory from a 1.203 registry, without the `requested_variants` and `cxx_stdlib` columns"""

    def test_negated_variants_and_no_cxx_stdlib(self):
        prefix = make_prefix(self.path("opt", "local"))
        portdb = os.path.join(prefix, "var", "macports")
        make_registry(portdb, schema="1.203", journal="delete",
                      ports=[port(1, "vim", "8.2.0", variants="+huge", negated_variants="-x11")])
        st = os.stat(prefix)
        inst = make_instance(Manager.PORTS, prefix=prefix, identity=(st.st_dev, st.st_ino), portdbpath=portdb,
                             drivable=False)
        inv = inventory.inventory(fake_runner(self.tmp), inst, FakePortIndex([PortEntry("vim", "8.2.0")]),
                                  platform=("darwin", 25))
        self.addCleanup(inv.close)
        vim = inv.packages[0]
        self.assertEqual((vim.requested_variants, vim.outdated, vim.spec_args),
                         (["-x11"], False, ["vim", "@8.2.0_0+huge"]))
        self.assertEqual(inv.schema_version, "1.203")


if __name__ == "__main__":
    unittest.main()

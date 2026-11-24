"""Packages installed twice: which packages of another installation the installation that stays has too"""

import os

from brew_ports import duplicates
from brew_ports.homebrew.catalogue import Catalogue
from brew_ports.model import Manager
from tests.unit.fixtures.doctor.builders import service
from tests.unit.fixtures.recommend.builders import Host
from tests.unit.helpers import TempDirTest, make_instance


class FindTest(TempDirTest):
    """A Mac with Homebrew and MacPorts, each of which may be the installation that stays"""

    def setUp(self):
        super().setUp()
        self.host = Host(self.tmp)
        self.brew = self.host.add_brew()
        self.ports = self.host.add_ports()

    def found(self, target):
        """Return the copies outside the installation that stays

        @param target  that installation
        @returns       each copy as (its installation's prefix, its name there, the name of the kept copy, what
                       needs it there)
        """
        found = duplicates.find(self.host.bundle(), target)
        self.assertIsNotNone(found)
        return [(d.other.prefix, d.name, d.kept, d.needed_by) for d in found or []]

    def test_the_same_name_and_a_known_equivalent_are_copies(self):
        for name in ("wget", "gnu-sed"):
            self.host.formula(name)
        for name, version in (("wget", "1.25.0"), ("gsed", "4.9"), ("gnutar", "1.35")):
            self.host.port(name, version)
        self.assertEqual(self.found(self.brew), [(self.ports.prefix, "gsed", "gnu-sed", []),
                                                 (self.ports.prefix, "wget", "wget", [])])
        # Whichever stays, the pairs are the same; gnutar has no copy in Homebrew.
        self.assertEqual(self.found(self.ports), [(self.brew.prefix, "gnu-sed", "gsed", []),
                                                  (self.brew.prefix, "wget", "wget", [])])

    def test_a_dependency_is_a_copy_too_and_names_what_needs_it(self):
        self.host.formula("wget")
        self.host.port("wget", "1.25.0", requested=False)
        self.host.port("gnutar", "1.35", deps=["wget"])
        self.assertEqual(self.found(self.brew), [(self.ports.prefix, "wget", "wget", ["gnutar"])])

    def test_another_major_version_is_no_copy(self):
        """As in a plan: libfoo 1 of MacPorts is replaced by nothing that Homebrew's libfoo 2 stands for"""
        self.host.formula("libfoo")
        self.host.port("libfoo", "1.4.0")
        self.assertEqual(self.found(self.brew), [])

    def test_a_closest_match_is_no_copy(self):
        self.host.formula("foobar")
        self.host.port("foo_bar", "2.3")
        self.assertEqual(self.found(self.brew), [])

    def test_a_stored_version_and_an_app_are_no_copies(self):
        self.host.formula("wget")
        self.host.port("wget", active=False)
        self.host.cask("firefox")
        self.host.port("firefox-app")
        self.assertEqual(self.found(self.brew), [])
        self.assertEqual(self.found(self.ports), [])

    def test_a_port_carries_the_version_in_use_and_every_dependent(self):
        """`port uninstall` refuses a name alone beside a stored version, and refuses while any port needs it"""
        self.host.formula("wget")
        self.host.port("wget", "1.25.0", revision=1, requested=False)
        self.host.port("gnutar", "1.35", deps=["wget"], active=False)
        found = duplicates.find(self.host.bundle(), self.brew) or []
        self.assertEqual([(d.name, d.version, d.needed_by) for d in found], [("wget", "@1.25.0_1", ["gnutar"])])
        self.assertEqual(found[0].reasons(), ["is needed by 1 package there (gnutar)"])
        self.assertEqual(duplicates.uninstall(found[0], "arm64"),
                         f"sudo {self.ports.prefix}/bin/port uninstall wget @1.25.0_1")

    def test_what_ties_a_copy_there_is_named(self):
        """A copy that runs a service or is the login shell is the move's to uninstall, not the user's"""
        plist = "/Library/LaunchDaemons/org.macports.gsed.plist"
        self.host.formula("gnu-sed")
        self.host.port("gsed", "4.9", services=[service("org.macports.gsed", plist, self.ports.prefix, "gsed",
                                                        kind="port")])
        found = duplicates.find(self.host.bundle(), self.brew) or []
        self.assertEqual([(d.name, d.reasons()) for d in found], [("gsed", ["has the service org.macports.gsed"])])
        self.host.formula("wget")
        self.host.port("wget", "1.25.0")
        bundle = self.host.bundle()
        bundle.result.environment.update(login_shell=os.path.join(self.brew.prefix, "opt", "wget", "bin", "wget"),
                                         login_shell_prefix=self.brew.prefix)
        found = duplicates.find(bundle, self.ports) or []
        self.assertEqual([(d.name, d.held) for d in found], [("gnu-sed", []), ("wget", ["is your login shell"])])

    def test_a_copy_whose_manager_cannot_run_is_left_to_the_move(self):
        self.ports.drivable = False
        self.host.formula("wget")
        self.host.port("wget", "1.25.0")
        found = duplicates.find(self.host.bundle(), self.brew) or []
        self.assertEqual([d.reasons() for d in found],
                         [["cannot be uninstalled while the `port` command there does not run"]])

    def test_without_a_package_list_nothing_can_be_told(self):
        """No copy found is no proof that there is none, so the answer is None, not an empty list"""
        host = Host(self.path("bare"))
        ports = host.add_ports(index=False)
        brew = host.add_brew(catalogue=Catalogue(source="none", home=host.home))
        host.formula("wget")
        host.port("wget", "1.25.0")
        self.assertIsNone(duplicates.find(host.bundle(), ports))
        self.assertIsNone(duplicates.find(host.bundle(), brew))

    def test_a_second_homebrew_holds_copies_under_the_same_names(self):
        intel = self.host.add_brew(self.host.usr_local, arch="x86_64")
        self.host.formula("wget")
        self.host.formula("wget", intel.prefix)
        self.host.formula("gnu-tar", intel.prefix)
        self.assertEqual(self.found(self.brew), [(intel.prefix, "wget", "wget", [])])


class UninstallTest(TempDirTest):
    """The command that uninstalls the other copy, as the user types it"""

    def double(self, manager, prefix, name, **kw):
        """Return a copy of a package in an installation whose command is not on the PATH

        @param manager  that installation's manager
        @param prefix   its prefix
        @param name     the package's name there
        @param kw       `Instance` fields
        @returns        the copy
        """
        return duplicates.Double(make_instance(manager, prefix, **kw), name, name)

    def test_a_port_is_uninstalled_under_sudo_by_its_version(self):
        double = self.double(Manager.PORTS, "/x/local", "jq")
        self.assertEqual(duplicates.uninstall(double, "arm64"), "sudo /x/local/bin/port uninstall jq")
        double.version = "@1.7.1_0+universal"
        self.assertEqual(duplicates.uninstall(double, "arm64"),
                         "sudo /x/local/bin/port uninstall jq @1.7.1_0+universal")

    def test_a_formula_of_an_intel_homebrew_keeps_the_arch_wrapper(self):
        double = self.double(Manager.BREW, "/x/usr/local", "jq", arch="x86_64")
        self.assertEqual(duplicates.uninstall(double, "arm64"),
                         "arch -x86_64 /x/usr/local/bin/brew uninstall --formula jq")
        self.assertEqual(duplicates.uninstall(self.double(Manager.BREW, "/x/homebrew", "jq"), "arm64"),
                         "/x/homebrew/bin/brew uninstall --formula jq")

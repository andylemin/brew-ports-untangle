"""The resolver's stages in their order, the version gate, interpreters, `--replace` and what maps to nothing"""

import unittest

from brew_ports.equiv import resolver
from brew_ports.equiv.resolver import Context, resolve
from brew_ports.model import Confidence, Manager
from tests.unit.fixtures.equiv.builders import BREW_SOURCE, brew_context, formula, port, ports_context
from tests.unit.helpers import TempDirTest, make_package

EXACT, HIGH, MEDIUM, LOW, NONE = (Confidence.EXACT, Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW,
                                  Confidence.NONE)
# MacPorts' Tcl and Tk at the versions of the macports-ports tree: the metaports tcl and tk, and Tcl's subports
TCL = {"name": "tcl", "version": "8.6.18", "homepage": "https://www.tcl-lang.org/"}
TCL_PORTS = [TCL, dict(TCL, name="tcl8"), dict(TCL, name="tcl9", version="9.0.4"), dict(TCL, name="tk")]


class ResolverCase(TempDirTest):
    """The resolver tests' mappings into either fixture target, and their assertions"""

    def into_brew(self, pkg, **kw):
        """Return the mapping of a package into the fixture Homebrew target

        @param pkg  the source package
        @param kw   more context fields
        @returns    the mapping
        """
        return resolve(pkg, brew_context(self.tmp, **kw))

    def into_ports(self, pkg, **kw):
        """Return the mapping of a package into the fixture MacPorts target

        @param pkg  the source package
        @param kw   more context fields, or the PortIndex's `drop` and `add`
        @returns    the mapping
        """
        return resolve(pkg, ports_context(self.tmp, **kw))

    def assert_mapped(self, mapping, kind, name, confidence, version=None):
        """Assert a mapping's target and confidence, showing its evidence on a failure

        @param mapping     the mapping
        @param kind        the target kind it should have
        @param name        the target name it should have, or None
        @param confidence  the confidence it should have
        @param version     the target version it should have; None leaves it unchecked
        """
        self.assertEqual((mapping.target_kind, mapping.target_name, mapping.confidence), (kind, name, confidence),
                         mapping.evidence)
        if version is not None:
            self.assertEqual(mapping.target_version, version)

    def assert_evidence(self, mapping, text):
        """Assert that one of a mapping's evidence lines holds a text

        @param mapping  the mapping
        @param text     the text
        """
        self.assertTrue(any(text in line for line in mapping.evidence), f"{text!r} not in {mapping.evidence!r}")


class StaticMapStageTest(ResolverCase):
    """The static map stage, whose pairs pass the version gate too"""

    def test_a_pair_into_macports(self):
        m = self.into_ports(formula("gnu-tar"))
        self.assert_mapped(m, "port", "gnutar", EXACT, "1.35_0")
        self.assertTrue(m.evidence[0].startswith("static map: gnu-tar = gnutar"))

    def test_a_versioned_formula_meets_its_pair(self):
        self.assert_mapped(self.into_ports(make_package("icu4c@78", prefix=BREW_SOURCE, version="78.2")),
                           "port", "icu", EXACT, "78.3_0")

    def test_gate_finds_the_versioned_formula(self):
        m = self.into_brew(port("icu", "78.3"))
        self.assert_mapped(m, "formula", "icu4c@78", HIGH, "78.2")
        self.assert_evidence(m, "static map: icu4c = icu")
        self.assert_evidence(m, "major 78 matched by icu4c@78")

    def test_tcl_tk_maps_to_tcl_with_tk_beside_it(self):
        m = self.into_ports(formula("tcl-tk@8"), add=TCL_PORTS)
        self.assert_mapped(m, "port", "tcl", EXACT, "8.6.18_0")
        self.assertEqual(m.companions, ["tk"])
        self.assertTrue(m.evidence[0].startswith("static map: tcl-tk = tcl + tk (Tcl and Tk;"), m.evidence)

    def test_tcl_tk_9_meets_tcl9_with_tk_beside_it(self):
        m = self.into_ports(formula("tcl-tk"), add=TCL_PORTS)
        self.assert_mapped(m, "port", "tcl9", HIGH, "9.0.4_0")
        self.assertEqual(m.companions, ["tk"])
        self.assert_evidence(m, "major 9 matched by tcl9")

    def test_a_missing_companion_is_noted(self):
        m = self.into_ports(formula("tcl-tk@8"), add=TCL_PORTS[:3])
        self.assert_mapped(m, "port", "tcl", EXACT)
        self.assertEqual(m.companions, [])
        self.assert_evidence(m, "companion tk is not in the MacPorts catalogue")

    def test_tcl_and_tk_map_back_to_tcl_tk(self):
        for name in ("tcl", "tk"):
            with self.subTest(port=name):
                m = self.into_brew(port(name, "8.6.18"))
                self.assert_mapped(m, "formula", "tcl-tk@8", HIGH, "8.6.18")
                self.assertEqual(m.companions, [])

    def test_a_pair_whose_target_is_missing_is_ignored(self):
        m = self.into_ports(formula("glib"), drop=["glib2"])
        self.assertIsNone(m.target_name)
        self.assert_evidence(m, "static map: glib = glib2 ignored, the MacPorts catalogue lacks glib2")
        self.assert_mapped(self.into_ports(formula("glib")), "port", "glib2", EXACT, "2.88.3_0")


class NameStageTest(ResolverCase):
    """The name stage: an identical name, aliases and case, then `canon()` matches and their corroboration"""

    def test_an_identical_name_is_exact(self):
        m = self.into_ports(formula("wget"))
        self.assert_mapped(m, "port", "wget", EXACT, "1.25.0_1")
        self.assertEqual(m.evidence[0], "name: wget")

    def test_aliases_and_case_count_as_the_name(self):
        m = self.into_brew(port("gsed", "4.9"))
        self.assert_mapped(m, "formula", "gnu-sed", EXACT, "4.10")
        self.assert_evidence(m, "gsed is gnu-sed in the Homebrew catalogue")
        self.assert_mapped(self.into_brew(port("ImageMagick", "7.1.2-8")), "formula", "imagemagick", EXACT)

    def test_a_canon_only_match_is_medium(self):
        m = self.into_brew(port("dd_rescue", "1.99.21", homepage="https://www.garloff.de/kurt/linux/ddrescue/",
                                executables=["dd_rescue"]))
        self.assert_mapped(m, "formula", "ddrescue", MEDIUM)
        self.assertEqual(m.evidence[0], "canonical name: dd_rescue ~ ddrescue (ddrescue)")

    def test_canon_match_with_executables_is_high(self):
        m = self.into_brew(port("the_silver_searcher", "2.2.0", executables=["ag"]))
        self.assert_mapped(m, "formula", "the-silver-searcher", HIGH)
        self.assert_evidence(m, "corroborated by the executables (Jaccard 1.00)")

    def test_canon_match_with_the_homepage_is_high(self):
        m = self.into_ports(formula("gtk+3"))
        self.assert_mapped(m, "port", "gtk3", HIGH)
        self.assert_evidence(m, "corroborated by the homepage https://gtk.org")
        self.assert_mapped(self.into_ports(formula("postgresql@16")), "port", "postgresql16", HIGH)

    def test_several_matches_are_resolved_by_the_gate(self):
        self.assert_mapped(self.into_brew(port("foo_bar", "2.3")), "formula", "foobar", MEDIUM, "2.0.1")

    def test_unresolved_matches_stay_medium_and_listed(self):
        m = self.into_brew(port("foo_bar", "3.0"))
        self.assert_mapped(m, "formula", "foobar", MEDIUM)
        self.assert_evidence(m, "no match has the source's major (3.0): foo-bar 1.2.0, foobar 2.0.1")

    def test_uncorroborated_other_major_is_dropped(self):
        m = self.into_brew(port("dd_rescue", "2.0", executables=["dd_rescue"]))
        self.assertEqual(m.confidence, LOW)          # the fuzzy stage lists it, never accepted
        self.assert_evidence(m, "version: ddrescue 1.29 has another major than the source 2.0")


class ExecutableStageTest(ResolverCase):
    """The executables stage into Homebrew: Jaccard over the executable aliases"""

    def test_gnutar_against_gtar(self):
        m = self.into_brew(port("tar-gnu-mp", "1.35", executables=["gnutar"]))
        self.assert_mapped(m, "formula", "gnu-tar", HIGH)
        self.assertEqual(m.evidence[0], "executables: tar-gnu-mp and gnu-tar (Jaccard 1.00)")

    def test_gcc_mp_15_against_gcc(self):
        m = self.into_brew(port("xgcc", "15.3.0", executables=["gcc-mp-15", "g++-mp-15", "cpp-mp-15"]))
        self.assert_mapped(m, "formula", "gcc", HIGH, "15.2.0")
        self.assert_evidence(m, "Jaccard 0.75")

    def test_gate_moves_executable_match_to_sibling(self):
        m = self.into_brew(port("xgcc", "14.2.0", executables=["gcc-mp-14", "g++-mp-14", "cpp-mp-14"]))
        self.assert_mapped(m, "formula", "gcc@14", HIGH, "14.3.0")

    def test_a_unique_match_below_half_is_medium(self):
        m = self.into_brew(port("ag-tools", "2.2", executables=["ag", "ag-index", "ag-report"]))
        self.assert_mapped(m, "formula", "the-silver-searcher", MEDIUM)

    def test_a_sole_match_of_another_major_is_named_with_its_option(self):
        m = self.into_brew(port("ag-tools", "9.0", executables=["ag", "ag-index", "ag-report"]))
        self.assert_mapped(m, "none", None, NONE)
        reason = m.evidence[0]
        self.assertTrue(reason.startswith("the closest find, formula the-silver-searcher "), reason)
        self.assertTrue(reason.endswith(" has another major version than 9.0; if it is the same software, plan with "
                                        "`--replace ag-tools=the-silver-searcher`"), reason)

    def test_several_weak_matches_give_nothing(self):
        m = self.into_brew(port("cc-mp", "15.0", executables=["gcc-mp-15"]))
        self.assertIsNone(m.target_name)
        self.assert_evidence(m, "other matches below 0.5")


class HomepageStageTest(ResolverCase):
    """The homepage stage: a unique target, else the version gate over several"""

    def test_a_unique_homepage_is_high(self):
        m = self.into_ports(formula("ddrescue"))
        self.assert_mapped(m, "port", "gddrescue", HIGH)
        self.assertTrue(m.evidence[0].startswith("homepage: https://gnu.org/software/ddrescue/ddrescue.html"))

    def test_same_major_homepages_give_the_newest(self):
        m = self.into_ports(formula("gcc-tools"))
        self.assert_mapped(m, "port", "gcc15", MEDIUM)
        self.assert_evidence(m, "gcc15 and libgcc15 share the source's major")


class VersionGateTest(ResolverCase):
    """The version gate: a sibling of the source's major, the nearest one, and `replaced_by`"""

    def test_a_sibling_with_the_source_major_wins(self):
        m = self.into_ports(formula("libfoo"))
        self.assert_mapped(m, "port", "libfoo2", HIGH, "2.1.3_0")
        self.assert_evidence(m, "major 2 matched by libfoo2")

    def test_no_sibling_gives_medium_naming_the_nearest(self):
        m = self.into_brew(port("ruby", "1.8.7-p374", revision=2))
        self.assert_mapped(m, "formula", "ruby", MEDIUM, "4.0.9")
        self.assert_evidence(m, "target is 4.0.9, source is 1.8.7-p374; nearest sibling ruby@3.4 3.4.7")

    def test_replaced_by_is_followed_before_the_gate(self):
        m = self.into_ports(make_package("gnome-themes-standard", prefix=BREW_SOURCE, version="48.0"))
        self.assert_mapped(m, "port", "adwaita-icon-theme", EXACT, "48.1_0")
        self.assert_evidence(m, "gnome-themes-standard is replaced by adwaita-icon-theme")

    def test_a_map_target_is_replaced_too(self):
        m = self.into_ports(make_package("temurin17", prefix=BREW_SOURCE, version="17.0.12"),
                            maps={"temurin17": "openjdk"})
        self.assert_mapped(m, "port", "openjdk17", EXACT, "17.0.17_0")
        self.assert_evidence(m, "openjdk is replaced by openjdk17")


class InterpreterTest(ResolverCase):
    """Interpreters in both directions, with their MacPorts companions and `port select` pairs"""

    def test_python_brings_pip_and_two_selections(self):
        m = self.into_ports(formula("python@3.13"))
        self.assert_mapped(m, "port", "python313", EXACT, "3.13.18_0")
        self.assertEqual(m.companions, ["py313-pip"])
        self.assertEqual(m.selections, [("python3", "python313"), ("pip3", "pip313")])

    def test_python_without_pip_port_selects_no_pip(self):
        m = self.into_ports(formula("python@3.14"))
        self.assert_mapped(m, "port", "python314", EXACT)
        self.assertEqual((m.companions, m.selections), ([], [("python3", "python314")]))
        self.assert_evidence(m, "companion py314-pip is not in the MacPorts catalogue")

    def test_node_takes_its_major_and_the_newest_npm(self):
        m = self.into_ports(formula("node"))
        self.assert_mapped(m, "port", "nodejs26", EXACT)
        self.assertEqual(m.companions, ["npm11"])
        self.assert_mapped(self.into_ports(formula("node@22")), "port", "nodejs22", EXACT)

    def test_ruby_4_maps_to_ruby40_not_the_1_8_port(self):
        m = self.into_ports(formula("ruby"))
        self.assert_mapped(m, "port", "ruby40", EXACT, "4.0.9_0")
        self.assertEqual(m.selections, [("ruby", "ruby40")])

    def test_without_ruby40_the_nearest_sibling_is_medium(self):
        ctx = ports_context(self.tmp, drop=["ruby40"])
        m = resolve(formula("ruby"), ctx)
        self.assert_mapped(m, "port", "ruby34", MEDIUM)
        self.assertEqual(m.evidence[0], "interpreter: no ruby40 in the MacPorts catalogue; source is 4.0.9; "
                                        "nearest sibling ruby34 3.4.12")
        self.assertFalse(resolver.accepted(m, ctx))
        self.assertTrue(resolver.accepted(m, ctx, answer=True))

    def test_perl_gcc_llvm_and_openjdk(self):
        self.assert_mapped(self.into_ports(formula("perl")), "port", "perl5", EXACT)
        gcc = self.into_ports(formula("gcc"))
        self.assert_mapped(gcc, "port", "gcc15", EXACT)
        self.assertEqual(gcc.selections, [("gcc", "mp-gcc15")])
        llvm = self.into_ports(formula("llvm"))
        self.assert_mapped(llvm, "port", "llvm-21", EXACT)
        self.assertEqual((llvm.companions, llvm.selections), (["clang-21"], [("clang", "mp-clang-21")]))
        self.assert_mapped(self.into_ports(formula("openjdk@21")), "port", "openjdk21", EXACT)
        self.assert_mapped(self.into_ports(formula("openjdk")), "port", "openjdk27", EXACT)

    def test_back_into_homebrew(self):
        cases = [
            (port("python313", "3.13.18"), "python@3.13"), (port("nodejs22", "22.23.4"), "node@22"),
            (port("nodejs26", "26.13.0"), "node"), (port("ruby34", "3.4.12"), "ruby@3.4"),
            (port("ruby40", "4.0.9"), "ruby"), (port("clang-19", "19.1.7"), "llvm@19"),
            (port("llvm-21", "21.1.8"), "llvm"), (port("gcc15", "15.3.0"), "gcc"), (port("gcc14", "14.3.0"), "gcc@14"),
            (port("perl5.40", "5.40.4"), "perl"), (port("openjdk21", "21.0.13.0.3"), "openjdk@21"),
        ]
        for pkg, name in cases:
            with self.subTest(port=pkg.name):
                m = self.into_brew(pkg)
                self.assert_mapped(m, "formula", name, EXACT)
                self.assertEqual((m.companions, m.selections), ([], []))

    def test_pip_and_npm_are_included_in_their_interpreter(self):
        m = self.into_brew(port("py313-pip", "26.2.2"))
        self.assert_mapped(m, "formula", "python@3.13", EXACT)
        self.assertEqual(m.evidence[0], "interpreter: py313-pip is included in python@3.13")
        self.assert_evidence(m, "not gated: py313-pip follows its own version line")
        self.assert_mapped(self.into_brew(port("npm10", "10.9.8", deps=["nodejs22"])), "formula", "node@22", EXACT)
        self.assert_mapped(self.into_brew(port("npm11", "11.21.0")), "formula", "node", EXACT)


class MapOverrideTest(ResolverCase):
    """`--replace OLD=NEW`: the target it names, its errors and the parser"""

    def test_map_names_the_target(self):
        m = self.into_brew(port("dd_rescue", "1.99"), maps={"dd_rescue": "ddrescue"})
        self.assert_mapped(m, "formula", "ddrescue", EXACT, "1.29")
        self.assertEqual(m.evidence[0], "your choice: --replace dd_rescue=ddrescue")

    def test_a_map_target_must_be_in_the_catalogue(self):
        ctx = brew_context(self.tmp, maps={"dd_rescue": "no-such"})
        m = resolve(port("dd_rescue", "1.99"), ctx)
        self.assert_mapped(m, "none", None, NONE)
        self.assertEqual(m.evidence[0], "no-such, which you chose with --replace, is not in Homebrew's package list")
        self.assertIsNone(resolver.target_known(ctx, "no-such"))
        self.assertEqual(resolver.target_known(ctx, "gsed"), ("formula", "gnu-sed"))
        self.assertEqual(resolver.target_known(ctx, "docker"), ("cask", "docker-desktop"))
        self.assertEqual(resolver.map_error(port("dd_rescue", "1.99"), ctx),
                         "--replace dd_rescue=no-such: Homebrew's package list has no no-such")

    def test_map_errors_spare_projects_and_known_targets(self):
        ctx = brew_context(self.tmp, maps={"py313-serial": "pyserial", "dd_rescue": "ddrescue"})
        self.assertIsNone(resolver.map_error(port("py313-serial", "3.5"), ctx))
        self.assertIsNone(resolver.map_error(port("dd_rescue", "1.99"), ctx))
        self.assertIsNone(resolver.map_error(port("wget", "1.25.0"), ctx))
        into_ports = ports_context(self.tmp, maps={"glib": "no-such", "black": "black"})
        self.assertIsNotNone(resolver.map_error(formula("glib"), into_ports))
        self.assertIsNone(resolver.map_error(formula("black"), into_ports))

    def test_map_keeps_a_target_of_another_major(self):
        m = self.into_brew(port("ruby", "1.8.7-p374"), maps={"ruby": "ruby@3.4"})
        self.assert_mapped(m, "formula", "ruby@3.4", EXACT)
        self.assert_evidence(m, "the major version differs; --replace keeps your choice")

    def test_parse_maps(self):
        self.assertEqual(resolver.parse_maps(["a=b", " c = d "]), {"a": "b", "c": "d"})
        self.assertEqual(resolver.parse_maps(None), {})
        for bad in ("a", "=b", "a="):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    resolver.parse_maps([bad])


class NegativeTest(ResolverCase):
    """What maps to nothing or stays below acceptance, refusals, and the acceptance rule itself"""

    def test_no_equivalent(self):
        ctx = brew_context(self.tmp)
        m = resolve(port("xyzzy", "1.0"), ctx)
        self.assert_mapped(m, "none", None, NONE)
        self.assertEqual(m.evidence, ["nothing of that name, or like it, is in Homebrew's package list"])
        self.assertFalse(resolver.accepted(m, ctx))
        self.assertEqual(len(resolver.NO_EQUIVALENT_SUGGESTIONS), 3)

    def test_refused_target_suggests_its_replacement(self):
        ctx = brew_context(self.tmp)
        m = resolve(port("apophenia", "1.0"), ctx)
        self.assert_mapped(m, "formula", "apophenia", NONE)
        self.assertEqual(m.evidence[0], "Homebrew has disabled apophenia (since 2026-05-16: unmaintained); it names "
                                        "gsl in its place: plan with `--replace apophenia=gsl`")
        self.assertFalse(resolver.accepted(m, ctx))
        refused = resolve(port("apophenia", "1.0"), brew_context(self.tmp, maps={"apophenia": "apophenia"}))
        self.assertEqual(refused.confidence, NONE)

    def test_a_deprecated_target_is_accepted(self):
        self.assert_mapped(self.into_brew(port("aamath", "0.3")), "formula", "aamath", EXACT)

    def test_the_fuzzy_match_is_low(self):
        ctx = brew_context(self.tmp)
        m = resolve(port("libpng16", "1.6.50"), ctx)
        self.assert_mapped(m, "formula", "libpng", LOW)
        self.assertEqual(m.evidence[0], "Homebrew's package list has similar names only (libpng); if one is the same "
                                        "software, plan with `--replace libpng16=` and that name")
        self.assertFalse(resolver.accepted(m, ctx))
        self.assert_mapped(self.into_brew(port("lz9", "1.0")), "none", None, NONE)

    def test_without_a_target_catalogue(self):
        m = resolve(port("wget", "1.25.0"), Context(target=Manager.BREW))
        self.assertEqual((m.confidence, m.evidence), (NONE, ["this Mac has no package list for Homebrew yet"]))

    def test_requested_variants_are_noted(self):
        m = self.into_brew(port("wget", "1.25.0", requested_variants=["+ssl", "-idn"]))
        self.assertEqual(m.variants_note, "requested variants +ssl -idn")
        self.assertIsNone(self.into_brew(port("wget", "1.25.0")).variants_note)

    def test_same_manager_by_name(self):
        m = self.into_brew(formula("wget"))
        self.assert_mapped(m, "formula", "wget", EXACT, "1.25.0_2")

    def test_acceptance(self):
        ctx = brew_context(self.tmp)
        pkg = port("wget")
        def mapping(confidence, kind="formula", name="wget"):
            return resolver.model.Mapping(pkg, kind, name, None, confidence, [], [], [], None)
        self.assertTrue(resolver.accepted(mapping(EXACT), ctx))
        self.assertTrue(resolver.accepted(mapping(HIGH), ctx))
        self.assertFalse(resolver.accepted(mapping(MEDIUM), ctx))
        self.assertTrue(resolver.accepted(mapping(MEDIUM), brew_context(self.tmp, accept_medium=True)))
        self.assertFalse(resolver.accepted(mapping(LOW), ctx, answer=True))
        self.assertFalse(resolver.accepted(mapping(HIGH, "pip", "serial"), ctx))
        self.assertTrue(resolver.accepted(mapping(HIGH, "pip", "serial"), brew_context(self.tmp, lang_packages="pipx")))
        self.assertFalse(resolver.accepted(mapping(EXACT, "formula", None), ctx))


if __name__ == "__main__":
    unittest.main()

"""The Python rule in both directions, language mappings with and without `--pipx`, and the plan's Python"""

import unittest

from brew_ports import runner as runner_mod
from brew_ports.equiv import resolver
from brew_ports.equiv.resolver import resolve
from brew_ports.model import Confidence
from tests.unit.fixtures.equiv.builders import (brew_context, formula, port, ports_context, pypi_page, pypi_url,
                                                web_runner)
from tests.unit.helpers import TempDirTest

EXACT, HIGH, LOW, NONE = Confidence.EXACT, Confidence.HIGH, Confidence.LOW, Confidence.NONE
SERIAL_HOME = "https://github.com/pyserial/pyserial"


class PythonCase(TempDirTest):
    """The Python tests' contexts and assertions; `seen` keeps every curl argv"""

    def setUp(self):
        super().setUp()
        self.seen = []

    def pipx(self, pages=None, **kw):
        """Return a Homebrew context under `--pipx` whose curl reaches only `pages`

        @param pages  the PyPI answers by URL; None for none, so every lookup is a 404
        @param kw     more context fields
        @returns      the context
        """
        return brew_context(self.tmp, lang_packages="pipx", runner=web_runner(self.tmp, pages or {}, self.seen),
                            downloads=self.path("downloads"), **kw)

    def assert_mapped(self, mapping, kind, name, confidence):
        """Assert a mapping's target and confidence, showing its evidence on a failure

        @param mapping     the mapping
        @param kind        the target kind it should have
        @param name        the target name it should have, or None
        @param confidence  the confidence it should have
        """
        self.assertEqual((mapping.target_kind, mapping.target_name, mapping.confidence), (kind, name, confidence),
                         mapping.evidence)

    def assert_evidence(self, mapping, text):
        """Assert that one of a mapping's evidence lines holds a text

        @param mapping  the mapping
        @param text     the text
        """
        self.assertTrue(any(text in line for line in mapping.evidence), f"{text!r} not in {mapping.evidence!r}")


class PortsIntoHomebrewTest(PythonCase):
    """Python module ports into Homebrew: the Python rule, then a `pip` language mapping"""

    def test_py313_numpy_is_numpy(self):
        m = resolve(port("py313-numpy", "2.5.4", homepage="https://numpy.org"), brew_context(self.tmp))
        self.assert_mapped(m, "formula", "numpy", EXACT)
        self.assertEqual(m.evidence[0], "python: py313-numpy is numpy, a Python package for python@3.13")

    def test_py313_requests_is_python_requests(self):
        m = resolve(port("py313-requests", "2.34.2"), brew_context(self.tmp))
        self.assert_mapped(m, "formula", "python-requests", EXACT)

    def test_formula_for_another_python_is_language(self):
        m = resolve(port("py313-numpy", "2.5.4"), brew_context(self.tmp, python_version="3.12"))
        self.assert_mapped(m, "pip", None, LOW)
        self.assert_evidence(m, "python: numpy is built for python@3.13, python@3.14, not python@3.12")

    def test_the_c_library_of_the_bare_name_is_never_taken(self):
        m = resolve(port("py313-cairo", "1.28.0", homepage="https://www.cairographics.org/pycairo/"),
                    brew_context(self.tmp))
        self.assert_mapped(m, "pip", None, LOW)
        self.assert_evidence(m, "python: cairo needs no Python at run or test time, so it is no Python package")

    def test_serial_under_report_lists_the_names_tried(self):
        ctx = brew_context(self.tmp, runner=web_runner(self.tmp, {}, self.seen))
        m = resolve(port("py313-serial", "3.5", homepage=SERIAL_HOME, executables=["pyserial-miniterm-3.13"]), ctx)
        self.assert_mapped(m, "pip", None, LOW)
        self.assertEqual(m.evidence[0], "language package (pip): tried serial")
        self.assertTrue(resolver.is_language(m))
        self.assertEqual(resolver.language_hints(m), ["serial"])
        self.assertFalse(resolver.accepted(m, ctx))
        self.assertEqual(self.seen, [])                 # report never goes to PyPI

    def test_port_without_pypi_homepage_tries_names(self):
        plain = resolve(port("py313-ruamel_yaml", "0.18.16", homepage="https://sourceforge.net/projects/ruamel-yaml/"),
                        brew_context(self.tmp))
        self.assertEqual(resolver.language_hints(plain), ["ruamel_yaml", "ruamel-yaml"])
        pypi = resolve(port("py313-serial", "3.5", homepage="https://pypi.org/project/pyserial/"),
                       brew_context(self.tmp))
        self.assertEqual(resolver.language_hints(pypi), ["pyserial", "serial"])
        self.assertEqual(pypi.evidence[0], "language package (pip): tried pyserial, serial")

    def test_serial_under_pipx_is_rejected_by_its_homepage(self):
        ctx = self.pipx({pypi_url("serial"): pypi_page("serial", {"Homepage": "https://github.com/someone/serial"})})
        m = resolve(port("py313-serial", "3.5", homepage=SERIAL_HOME, executables=["pyserial-miniterm-3.13"]), ctx)
        self.assert_mapped(m, "pip", None, LOW)
        self.assertEqual(m.evidence[0], "no PyPI project matches its homepage")
        self.assert_evidence(m, "pypi: serial does not list https://github.com/pyserial/pyserial")
        self.assertEqual(self.seen[0][-1], "https://pypi.org/pypi/serial/json")
        self.assertFalse(resolver.accepted(m, ctx))

    def test_serial_named_by_map_is_pip_pyserial(self):
        source = port("py313-serial", "3.5", homepage=SERIAL_HOME, executables=["pyserial-miniterm-3.13"])
        ctx = self.pipx(maps={"py313-serial": "pyserial"})
        m = resolve(source, ctx)
        self.assert_mapped(m, "pip", "pyserial", HIGH)
        self.assertEqual(m.companions, ["pipx"])
        self.assertTrue(resolver.accepted(m, ctx))
        self.assertEqual(self.seen, [])                 # --replace names the project: no homepage check
        report = brew_context(self.tmp, maps={"py313-serial": "pyserial"})
        named = resolve(source, report)
        self.assert_mapped(named, "pip", "pyserial", LOW)
        self.assertFalse(resolver.accepted(named, report))
        self.assertEqual(resolver.language_hints(named), ["pyserial"])

    def test_a_pypi_homepage_names_the_project(self):
        pages = {pypi_url("tomli-w"): pypi_page("tomli-w", {}, version="1.2.0")}
        library = resolve(port("py313-tomli-w", "1.2.0", homepage="https://pypi.org/project/tomli-w/"),
                          self.pipx(pages))
        self.assert_mapped(library, "pip", "tomli-w", LOW)
        self.assert_evidence(library, "tomli-w installs no executable, so pipx does not take it")
        tool = resolve(port("py313-tomli-w", "1.2.0", homepage="https://pypi.org/project/tomli-w/",
                            executables=["tomli-w-3.13"]), self.pipx(pages))
        self.assert_mapped(tool, "pip", "tomli-w", HIGH)
        self.assertEqual((tool.target_version, tool.companions), ("1.2.0", ["pipx"]))

    def test_a_pypi_404_or_failure_matches_nothing(self):
        missing = resolve(port("py313-serial", "3.5", homepage=SERIAL_HOME, executables=["x"]), self.pipx())
        self.assert_evidence(missing, "pypi: no project serial")
        down = runner_mod.FakeResponse(exit=6, stderr="curl: (6) Could not resolve host: pypi.org\n")
        failed = resolve(port("py313-serial", "3.5", homepage=SERIAL_HOME, executables=["x"]),
                         self.pipx({pypi_url("serial"): down}))
        self.assertEqual(failed.evidence[0], "no PyPI project matches its homepage")
        self.assert_evidence(failed, "pypi: serial: curl: (6) Could not resolve host: pypi.org")

    def test_pipx_without_a_runner_checks_nothing(self):
        m = resolve(port("py313-serial", "3.5", homepage=SERIAL_HOME, executables=["x"]),
                    brew_context(self.tmp, lang_packages="pipx"))
        self.assert_mapped(m, "pip", None, LOW)
        self.assert_evidence(m, "pypi: not checked, no runner")

    def test_perl_and_ruby_modules_are_language(self):
        for ctx in (brew_context(self.tmp), self.pipx()):
            with self.subTest(lang=ctx.lang_packages):
                cpan = resolve(port("p5.34-uri", "5.31.0"), ctx)
                self.assert_mapped(cpan, "cpan", None, LOW)
                self.assertEqual(cpan.evidence[0], "language package (cpan): tried uri")
                self.assert_mapped(resolve(port("rb33-rake", "13.3.0"), ctx), "gem", None, LOW)
        self.assertEqual(self.seen, [])


class HomebrewIntoMacPortsTest(PythonCase):
    """Python package formulae into MacPorts: the module port of the plan's Python, else a `pip` mapping"""

    def test_numpy_is_py313_numpy(self):
        m = resolve(formula("numpy"), ports_context(self.tmp))
        self.assert_mapped(m, "port", "py313-numpy", EXACT)
        self.assertEqual(m.evidence[0], "python: numpy is a Python package (python@3.13, python@3.14): py313-numpy "
                                        "for the plan's Python 3.13")

    def test_the_plan_python_picks_the_module_port(self):
        m = resolve(formula("numpy"), ports_context(self.tmp, python_version="3.14"))
        self.assert_mapped(m, "port", "py314-numpy", EXACT)

    def test_glib_stays_out_of_the_python_rule(self):
        ctx = ports_context(self.tmp, drop=["glib2"],
                            add=[{"name": "py313-glib", "version": "2.90.1", "homepage": "https://docs.gtk.org/glib/"}])
        m = resolve(formula("glib"), ctx)
        self.assert_mapped(m, "none", None, NONE)
        self.assertEqual(m.evidence[0], "nothing of that name, or like it, is in MacPorts' package list")
        self.assert_evidence(m, "python: glib needs python@3.13 only to build, so it is no Python package")

    def test_a_python_prefix_formula_drops_its_prefix(self):
        self.assert_mapped(resolve(formula("python-requests"), ports_context(self.tmp)), "port", "py313-requests",
                           EXACT)

    def test_a_python_application_finds_its_module_port(self):
        self.assert_mapped(resolve(formula("httpie"), ports_context(self.tmp)), "port", "py313-httpie", EXACT)

    def test_receipt_dependencies_without_catalogue(self):
        m = resolve(formula("httpie"), ports_context(self.tmp, source_catalogues={}))
        self.assert_mapped(m, "port", "py313-httpie", EXACT)
        self.assert_evidence(m, "python: from the receipt's runtime dependencies; /usr/local has no catalogue")

    def test_application_without_port_is_language(self):
        report = resolve(formula("black"), ports_context(self.tmp))
        self.assert_mapped(report, "pip", None, LOW)
        self.assertEqual(report.evidence[0], "language package (pip): tried black")
        self.assert_evidence(report, "python: no py313-black in the MacPorts catalogue")
        pages = {pypi_url("black"): pypi_page("black", {"Documentation": "https://black.readthedocs.io/en/stable/"},
                                               version="25.9.0")}
        ctx = ports_context(self.tmp, lang_packages="pipx", runner=web_runner(self.tmp, pages, self.seen),
                            downloads=self.path("downloads"))
        pipx = resolve(formula("black"), ctx)
        self.assert_mapped(pipx, "pip", "black", HIGH)
        self.assertEqual(pipx.companions, ["pipx"])
        self.assertTrue(resolver.accepted(pipx, ctx))


class PythonVersionTest(PythonCase):
    """The target's default Python, the plan's Python and the dependency tags behind the Python rule"""

    def test_the_homebrew_default_is_the_python3_alias(self):
        self.assertEqual(resolver.default_python(brew_context(self.tmp)), "3.13")

    def test_the_macports_default_needs_its_pip_port(self):
        self.assertEqual(resolver.default_python(ports_context(self.tmp)), "3.13")
        ctx = ports_context(self.tmp, add=[{"name": "py314-pip", "version": "26.2.2"}])
        self.assertEqual(resolver.default_python(ctx), "3.14")

    def test_the_plan_python_is_a_migrated_interpreter(self):
        ctx = ports_context(self.tmp)
        self.assertEqual(resolver.plan_python([port("python312", "3.12.10"), port("wget")], ctx), "3.12")
        self.assertEqual(resolver.plan_python([formula("python@3.14"), port("python313", "3.13.18")], ctx), "3.14")
        self.assertEqual(resolver.plan_python([port("py313-pip", "26.2.2")], ctx), "3.13")

    def test_dependency_tags(self):
        catalogue = brew_context(self.tmp).catalogue
        self.assertEqual(resolver.python_dependencies(catalogue, "glib"), [("3.13", True)])
        self.assertEqual(resolver.python_package_versions(catalogue, "glib"), [])
        self.assertEqual(resolver.python_package_versions(catalogue, "numpy"), ["3.13", "3.14"])
        self.assertEqual(resolver.python_package_versions(catalogue, "python-requests"), ["3.13"])
        self.assertEqual(resolver.python_package_versions(catalogue, "no-such-formula"), [])


if __name__ == "__main__":
    unittest.main()

"""Casks in the resolver: cask-only targets, adoption into Homebrew, and casks into MacPorts"""

import unittest

from brew_ports.equiv import resolver
from brew_ports.equiv.resolver import resolve
from brew_ports.model import Confidence
from tests.unit.fixtures.equiv.builders import BREW_TARGET, brew_context, cask, port, ports_context
from tests.unit.helpers import TempDirTest, make_package

EXACT, HIGH, NONE = Confidence.EXACT, Confidence.HIGH, Confidence.NONE
CONDA_BASE = "/usr/local/Caskroom/miniconda/base"


class CaskCase(TempDirTest):
    """The cask tests' assertion on a mapping"""

    def assert_mapped(self, mapping, kind, name, confidence, adopt=False):
        """Assert a mapping's target, confidence and adoption, showing its evidence on a failure

        @param mapping     the mapping
        @param kind        the target kind it should have
        @param name        the target name it should have, or None
        @param confidence  the confidence it should have
        @param adopt       whether it should adopt the cask in place
        """
        self.assertEqual((mapping.target_kind, mapping.target_name, mapping.confidence, mapping.adopt),
                         (kind, name, confidence, adopt), mapping.evidence)


class CaskTargetTest(CaskCase):
    """A port whose only Homebrew counterpart is a cask"""

    def test_a_cask_only_target(self):
        ctx = brew_context(self.tmp)
        m = resolve(port("videolan-player", "3.0.21", homepage="https://www.videolan.org/vlc/"), ctx)
        self.assert_mapped(m, "cask", "vlc", HIGH)
        self.assertEqual(m.target_version, "3.0.21")
        self.assertIn("version: cask vlc 3.0.21, not gated", m.evidence)
        self.assertTrue(resolver.accepted(m, ctx))

    def test_a_cask_only_target_that_needs_sudo_to_install(self):
        ctx = brew_context(self.tmp)
        m = resolve(port("zoom-client", "6.6", homepage="https://zoom.us/"), ctx)
        self.assert_mapped(m, "cask", "zoom", NONE)
        self.assertEqual(m.evidence[0], "cask needs sudo to install: run `brew install --cask zoom` on a terminal")
        self.assertFalse(resolver.accepted(m, ctx))


class AdoptionTest(CaskCase):
    """The adoption of a source cask into a Homebrew target, and what prevents it"""

    def test_a_source_cask_is_adopted_under_its_token(self):
        m = resolve(cask("firefox", "144.0"), brew_context(self.tmp))
        self.assert_mapped(m, "cask", "firefox", EXACT, adopt=True)
        self.assertEqual(m.target_version, "145.0")
        self.assertEqual(m.evidence[0], "adopt firefox: the same token in the target catalogue")

    def test_a_renamed_token_is_adopted_under_its_new_name(self):
        m = resolve(cask("docker", "4.40.0"), brew_context(self.tmp))
        self.assert_mapped(m, "cask", "docker-desktop", EXACT, adopt=True)
        self.assertIn("docker is docker-desktop in the Homebrew catalogue", m.evidence)

    def test_a_cask_the_target_holds_is_installed_already(self):
        ctx = brew_context(self.tmp, installed=[make_package("virtualbox", "cask", BREW_TARGET, version="7.2.4")])
        m = resolve(cask("virtualbox", "7.2.2"), ctx)
        self.assert_mapped(m, "cask", "virtualbox", EXACT, adopt=True)
        self.assertEqual(m.evidence[0], "adopt virtualbox: installed in the target")
        self.assertIsNotNone(resolver.installed_in_target(ctx, "cask", "VirtualBox"))
        self.assertIsNone(resolver.installed_in_target(ctx, "formula", "virtualbox"))

    def test_installed_refused_cask_stays_unmigratable(self):
        ctx = brew_context(self.tmp, installed=[make_package("1kc-razer", "cask", BREW_TARGET, version="0.4.10")])
        m = resolve(cask("1kc-razer", "0.4.9"), ctx)
        self.assert_mapped(m, "cask", "1kc-razer", NONE)
        self.assertTrue(m.evidence[0].startswith("Homebrew refuses to install 1kc-razer"))

    def test_an_installed_cask_only_target_needs_no_sudo(self):
        ctx = brew_context(self.tmp, installed=[make_package("zoom", "cask", BREW_TARGET, version="6.6.0")])
        m = resolve(port("zoom-client", "6.6", homepage="https://zoom.us/"), ctx)
        self.assert_mapped(m, "cask", "zoom", HIGH)

    def test_a_cask_that_needs_sudo_is_not_adopted(self):
        m = resolve(cask("virtualbox", "7.2.2"), brew_context(self.tmp))
        self.assert_mapped(m, "cask", "virtualbox", NONE)
        self.assertEqual(m.evidence[0], "cask needs sudo to install: run `brew install --cask --adopt virtualbox` "
                                        "on a terminal, then plan again")

    def test_a_refused_cask_is_not_adopted(self):
        m = resolve(cask("1kc-razer", "0.4.9"), brew_context(self.tmp))
        self.assert_mapped(m, "cask", "1kc-razer", NONE)
        self.assertEqual(m.evidence, ["Homebrew refuses to install 1kc-razer: disabled since 2026-09-01 "
                                      "(fails_gatekeeper_check)"])

    def test_a_cask_that_keeps_data_is_never_adopted(self):
        pkg = cask("miniconda", "py313_25.9.1-0", caskroom_data=[CONDA_BASE])
        m = resolve(pkg, brew_context(self.tmp))
        self.assert_mapped(m, "none", None, NONE)
        self.assertEqual(m.evidence, [f"keeps data in {CONDA_BASE}"])
        self.assertEqual(resolver.keeps_data(pkg), CONDA_BASE)
        self.assertIsNone(resolver.keeps_data(cask("firefox")))

    def test_map_never_moves_a_cask_that_keeps_data(self):
        pkg = cask("miniconda", "py313_25.9.1-0", caskroom_data=[CONDA_BASE])
        for context in (brew_context(self.tmp, maps={"miniconda": "miniconda"}),
                        ports_context(self.tmp, maps={"miniconda": "miniconda"})):
            with self.subTest(target=context.target):
                m = resolve(pkg, context)
                self.assert_mapped(m, "none", None, NONE)
                self.assertEqual(m.evidence, [f"keeps data in {CONDA_BASE}: --map miniconda=miniconda is refused"])

    def test_a_token_the_target_catalogue_lacks(self):
        m = resolve(cask("homemade", "1.0"), brew_context(self.tmp))
        self.assert_mapped(m, "none", None, NONE)
        self.assertEqual(m.evidence[0], "no equivalent in Homebrew catalogue: it has no cask homemade")


class CasksIntoMacPortsTest(CaskCase):
    """Casks into a MacPorts target: `-app` ports by homepage, fonts, data and `--map`"""

    def test_a_cask_maps_to_an_app_port_by_its_homepage(self):
        m = resolve(cask("firefox", "145.0", homepage="https://www.mozilla.org/firefox/"), ports_context(self.tmp))
        self.assert_mapped(m, "port", "firefox-app", HIGH)

    def test_only_app_ports_are_candidates(self):
        m = resolve(cask("firefox", "145.0", homepage="https://www.mozilla.org/firefox/"),
                    ports_context(self.tmp, drop=["firefox-app"]))
        self.assert_mapped(m, "none", None, NONE)
        self.assertEqual(m.evidence, ["no equivalent in MacPorts catalogue"])

    def test_font_casks_map_to_nothing(self):
        pkg = cask("font-fira-code", "6.2", homepage="https://github.com/tonsky/FiraCode")
        self.assertTrue(resolver.font_cask(pkg))
        m = resolve(pkg, ports_context(self.tmp))
        self.assertEqual((m.confidence, m.evidence), (NONE, ["font casks map to nothing: reinstall the font by hand"]))

    def test_a_cask_that_keeps_data_maps_to_nothing(self):
        m = resolve(cask("miniconda", caskroom_data=[CONDA_BASE]), ports_context(self.tmp))
        self.assertEqual(m.evidence, [f"keeps data in {CONDA_BASE}"])

    def test_map_names_the_port(self):
        m = resolve(cask("firefox", "145.0"), ports_context(self.tmp, maps={"firefox": "firefox-esr"}))
        self.assert_mapped(m, "port", "firefox-esr", EXACT)
        self.assertEqual(m.evidence[0], "--map firefox=firefox-esr")


if __name__ == "__main__":
    unittest.main()

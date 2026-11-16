"""The static map shipped in `brew_ports/data`: its curated pairs, their lookups and the parser"""

import unittest

from brew_ports.equiv import static_map
from brew_ports.equiv.static_map import Pair


class ShippedMapTest(unittest.TestCase):
    """The shipped pairs, looked up by either side's name, and the parser of an equivalents file"""

    def setUp(self):
        self.smap = static_map.shipped()

    def test_curated_pairs_are_shipped(self):
        pairs = {(p.brew, p.ports) for p in self.smap.pairs}
        for pair in [("node", "nodejs"), ("qt", "qt6"), ("pkg-config", "pkgconfig"), ("gnu-tar", "gnutar"),
                     ("wireshark", "wireshark4"), ("sqlite", "sqlite3"), ("glib", "glib2"), ("icu4c", "icu"),
                     ("sdl2", "libsdl2"), ("gnupg", "gnupg2"), ("make", "gmake"), ("jpeg-turbo", "libjpeg-turbo"),
                     ("pixman", "libpixman"), ("tcl-tk", "tcl")]:
            with self.subTest(pair=pair):
                self.assertIn(pair, pairs)

    def test_pairs_are_distinct_names_with_notes(self):
        seen: set[tuple[str, str]] = set()
        for pair in self.smap.pairs:
            with self.subTest(pair=pair):
                self.assertNotEqual(pair.brew.lower(), pair.ports.lower())
                self.assertTrue(pair.note)
                self.assertNotIn((pair.brew, pair.ports), seen)
                seen.add((pair.brew, pair.ports))

    def test_the_pkg_config_note_names_the_pkgconf_alias(self):
        [pair] = [p for p in self.smap.pairs if p.brew == "pkg-config"]
        self.assertIn("alias of pkgconf", pair.note)
        self.assertNotIn("separate entry in both", pair.note)
        [line] = [text for text in static_map.shipped_text().splitlines() if '"pkg-config"' in text]
        self.assertLess(len(line), 120)

    def test_formulae_match_with_or_without_version(self):
        self.assertEqual([p.ports for p in self.smap.ports_for("gnu-tar")], ["gnutar"])
        self.assertEqual([p.ports for p in self.smap.ports_for("icu4c@78")], ["icu"])
        self.assertEqual([p.ports for p in self.smap.ports_for("qt@5")], ["qt6"])
        self.assertEqual(self.smap.ports_for("wget"), [])
        self.assertEqual(self.smap.ports_for("python@3.13"), [])

    def test_port_names_match_case_insensitively(self):
        self.assertEqual([p.brew for p in self.smap.brew_for("GLIB2")], ["glib"])
        self.assertEqual([p.brew for p in self.smap.brew_for("libsdl2")], ["sdl2", "sdl2-compat"])
        self.assertEqual(self.smap.brew_for("wget"), [])

    def test_a_companion_port_comes_with_its_pair(self):
        self.assertEqual([(p.ports, p.companions) for p in self.smap.ports_for("tcl-tk@8")], [("tcl", ("tk",))])
        self.assertEqual([p.brew for p in self.smap.brew_for("TK")], ["tcl-tk"])
        self.assertEqual([p.brew for p in self.smap.brew_for("tcl")], ["tcl-tk"])

    def test_parse_skips_incomplete_entries(self):
        text = '[{"brew": "a", "ports": "b"}, {"brew": "c"}, "x", {"brew": 1, "ports": "d"}]'
        self.assertEqual(static_map.parse(text), [Pair("a", "b", "")])
        self.assertEqual(static_map.parse('{"brew": "a", "ports": "b"}'), [])
        text = '[{"brew": "a", "ports": "b", "companions": ["c", 2]}, {"brew": "d", "ports": "e", "companions": "f"}]'
        self.assertEqual(static_map.parse(text), [Pair("a", "b", "", ("c",)), Pair("d", "e", "")])


if __name__ == "__main__":
    unittest.main()

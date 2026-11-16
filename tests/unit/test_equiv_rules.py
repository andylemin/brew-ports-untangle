"""The naming rules of the equivalence resolver: canonical names, executable aliases, versions and name keys"""

import re
import unittest

from brew_ports.equiv import rules


class CanonTest(unittest.TestCase):
    """`canon`, which folds the Homebrew and MacPorts naming conventions onto one key"""

    def test_folds_both_conventions(self):
        table = [
            ("python@3.12", "python312"), ("postgresql@16", "postgresql16"), ("llvm@19", "llvm19"),
            ("llvm-19", "llvm19"), ("boost@1.85", "boost185"), ("boost185", "boost185"),
            ("mariadb@11.4", "mariadb114"), ("mariadb-11.4", "mariadb114"), ("gtk+3", "gtk3"), ("gtk3", "gtk3"),
            ("ImageMagick", "imagemagick"), ("gnu-sed", "gsed"), ("openssl@3", "openssl3"), ("lz4", "lz4"),
            ("dd_rescue", "ddrescue"), ("libxml++", "libxml"),
        ]
        for name, key in table:
            with self.subTest(name=name):
                self.assertEqual(rules.canon(name), key)

    def test_the_gnu_prefix_folds_only_at_the_start(self):
        self.assertEqual(rules.canon("libgnu-foo"), "libgnufoo")
        self.assertEqual(rules.canon("gnu-tar"), "gtar")
        self.assertNotEqual(rules.canon("gnu-tar"), rules.canon("gnutar"))


class ExeAliasTest(unittest.TestCase):
    """The executable aliases, the matches they give and the Jaccard score over them"""

    TABLE = [
        ("gnutar", {"gnutar", "gtar"}), ("gtar", {"gtar", "gnutar"}),
        ("gcc-mp-15", {"gcc-mp-15", "gcc"}), ("gcc-15", {"gcc-15", "gcc"}), ("gcc", {"gcc"}),
        ("g++-mp-15", {"g++-mp-15", "g++"}), ("gfortran", {"gfortran"}), ("cpp-14", {"cpp-14", "cpp"}),
        ("clang-mp-19", {"clang-mp-19", "clang"}), ("clang++-19", {"clang++-19", "clang++"}),
        ("lld-mp-19", {"lld-mp-19", "lld"}), ("lldb-19", {"lldb-19", "lldb"}),
        ("ruby3.4", {"ruby3.4", "ruby"}), ("gem3.4", {"gem3.4", "gem"}), ("irb", {"irb"}),
        ("rake3.3", {"rake3.3", "rake"}), ("bundle3.4", {"bundle3.4", "bundle"}),
        ("perl5.34", {"perl5.34", "perl"}), ("perl", {"perl"}),
        ("python3.12", {"python3.12", "python3"}), ("pip-3.12", {"pip-3.12", "pip3"}),
        ("pip3.12", {"pip3.12", "pip3"}), ("pip3", {"pip3"}), ("idle3.13", {"idle3.13", "idle3"}),
        ("pydoc3", {"pydoc3"}), ("wheel-3.12", {"wheel-3.12", "wheel3"}),
        ("wget", {"wget"}), ("python", {"python"}), ("gcc-ar-15", {"gcc-ar-15"}), ("ruby34", {"ruby34"}),
    ]

    def test_table(self):
        for name, aliases in self.TABLE:
            with self.subTest(name=name):
                self.assertEqual(rules.exe_aliases(name), aliases)

    def test_every_pattern_compiles_and_is_exercised(self):
        for pattern, suffix in rules.EXE_PATTERNS:
            with self.subTest(pattern=pattern.pattern):
                self.assertIsInstance(re.compile(pattern.pattern), re.Pattern)
                self.assertIsInstance(suffix, str)
                hits = [name for name, _ in self.TABLE if pattern.fullmatch(name)]
                self.assertTrue(hits, f"no table row exercises {pattern.pattern}")
                misses = [name for name, _ in self.TABLE if not pattern.fullmatch(name)]
                self.assertTrue(misses)

    def test_matches(self):
        for left, right in [("gnutar", "gtar"), ("gcc-mp-15", "gcc"), ("gcc-mp-15", "gcc-15"), ("pip-3.12", "pip3"),
                            ("pip-3.12", "pip3.12"), ("clang-mp-19", "clang"), ("ruby3.4", "ruby"),
                            ("perl5.34", "perl"), ("python3.12", "python3"), ("wget", "wget")]:
            with self.subTest(left=left, right=right):
                self.assertTrue(rules.exe_match(left, right))
                self.assertTrue(rules.exe_match(right, left))
        for left, right in [("gcc", "clang"), ("pip3", "python3"), ("gtar", "tar"), ("gcc-ar-15", "gcc"),
                            ("ruby34", "ruby")]:
            with self.subTest(left=left, right=right):
                self.assertFalse(rules.exe_match(left, right))

    def test_jaccard(self):
        self.assertEqual(rules.exe_jaccard(["gnutar"], ["gtar"]), 1.0)
        self.assertEqual(rules.exe_jaccard(["gcc-mp-15", "g++-mp-15", "cpp-mp-15"],
                                           ["gcc-15", "g++-15", "cpp-15", "gfortran"]), 0.75)
        self.assertAlmostEqual(rules.exe_jaccard(["a", "b"], ["b", "c"]), 1 / 3)
        self.assertEqual(rules.exe_jaccard([], ["x"]), 0.0)
        self.assertEqual(rules.exe_jaccard([], []), 0.0)


class VersionTest(unittest.TestCase):
    """Plain versions, majors and the closeness of two versions"""

    def test_plain_version(self):
        self.assertEqual(rules.plain_version("1.8.2_1"), "1.8.2")
        self.assertEqual(rules.plain_version("1.8.2_0+x11+universal"), "1.8.2")
        self.assertEqual(rules.plain_version("6.9.13-38_2"), "6.9.13-38")
        self.assertEqual(rules.plain_version("latest"), "latest")
        self.assertIsNone(rules.plain_version(None))

    def test_major(self):
        self.assertEqual(rules.major("1.8.7-p374_2"), 1)
        self.assertEqual(rules.major("v2.0"), 2)
        self.assertEqual(rules.major("26.13.0"), 26)
        self.assertIsNone(rules.major("latest"))
        self.assertIsNone(rules.major(None))

    def test_closeness(self):
        self.assertEqual(rules.closeness("4.0.9", "4.0.2"), (2, 7))
        self.assertEqual(rules.closeness("4.0.9", "3.4.12"), (0, 1))
        self.assertEqual(rules.closeness("3.13.18", "3.13.18_0"), (3, 0))


class NameKeyTest(unittest.TestCase):
    """The stem and fuzzy keys, language ports, Python versions and PyPI names"""

    def test_stem_and_fuzzy_key(self):
        self.assertEqual(rules.stem("ruby40"), "ruby")
        self.assertEqual(rules.stem("python@3.13"), "python")
        self.assertEqual(rules.stem("llvm-21"), "llvm")
        self.assertEqual(rules.stem("icu4c@78"), "icu4c")
        self.assertEqual(rules.fuzzy_key("libpng16"), "libpng")
        self.assertIsNone(rules.fuzzy_key("lz4"))

    def test_language_ports(self):
        self.assertEqual(rules.language_port("py313-serial"), ("pip", "serial"))
        self.assertEqual(rules.language_port("py-numpy"), ("pip", "numpy"))
        self.assertEqual(rules.language_port("p5.34-libwww-perl"), ("cpan", "libwww-perl"))
        self.assertEqual(rules.language_port("p5-uri"), ("cpan", "uri"))
        self.assertEqual(rules.language_port("rb33-rake"), ("gem", "rake"))
        for name in ("python313", "rbenv", "pyqt5", "perl5.40", "wget"):
            with self.subTest(name=name):
                self.assertIsNone(rules.language_port(name))

    def test_python_versions(self):
        self.assertEqual(rules.python_version_of("python@3.12"), "3.12")
        self.assertEqual(rules.python_version_of("python312"), "3.12")
        self.assertEqual(rules.python_version_of("python27"), "2.7")
        self.assertIsNone(rules.python_version_of("python3"))
        self.assertIsNone(rules.python_version_of("py313-pip"))
        self.assertEqual(rules.py_prefix("3.13"), "py313")

    def test_pypi_candidates(self):
        self.assertEqual(rules.pypi_candidates("serial"), ["serial"])
        self.assertEqual(rules.pypi_candidates("tomli-w"), ["tomli-w", "tomli_w"])
        self.assertEqual(rules.pypi_candidates("foo_bar", "https://pypi.org/project/foo-bar/"), ["foo-bar", "foo_bar"])
        self.assertEqual(rules.pypi_candidates("serial", "https://pypi.org/project/pyserial"), ["pyserial", "serial"])
        self.assertIsNone(rules.pypi_project("https://github.com/pyserial/pyserial"))


if __name__ == "__main__":
    unittest.main()

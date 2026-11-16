"""The PortIndex: sources.conf, the UTF-16 unit reader, the quick index and lookups with both list splitters"""

import io
import os
import unittest

from brew_ports.macports import portindex
from brew_ports.macports.portindex import PortIndex, PortIndexError
from brew_ports.model import Manager
from tests.unit.fixtures.macports.builders import (make_prefix, portindex_entries, tcl_splitlist, tkinter_available,
                                                   utf16_units, write_portindex, write_sources_conf)
from tests.unit.helpers import TempDirTest, make_instance


class SourcesTest(TempDirTest):
    """sources.conf, the tree of each kind of source, and the PortIndex of an instance"""

    def test_default_source(self):
        conf = self.write("sources.conf", "# comment\n\nfile:///Users/alice/ports\n"
                                          "rsync://rsync.macports.org/macports/release/tarballs/ports.tar [default]\n"
                                          "not a source line\n")
        self.assertEqual(portindex.default_source(conf),
                         "rsync://rsync.macports.org/macports/release/tarballs/ports.tar")
        flagged = self.write("flags.conf", "https://a.example/ports.tar.gz [nosync,default]\nfile:///b [nosync]\n")
        self.assertEqual(portindex.default_source(flagged), "https://a.example/ports.tar.gz")

    def test_without_a_default_the_last_source_is_used(self):
        conf = self.write("sources.conf", "file:///Users/alice/ports\nrsync://example.org/macports/release/ports/\n")
        self.assertEqual(portindex.default_source(conf), "rsync://example.org/macports/release/ports/")
        self.assertIsNone(portindex.default_source(self.path("missing.conf")))

    def test_source_directories_as_getsourcepath_builds_them(self):
        db = "/opt/local/var/macports"
        self.assertEqual(portindex.source_dir("rsync://rsync.macports.org/macports/release/tarballs/ports.tar", db),
                         db + "/sources/rsync.macports.org/macports/release/tarballs/ports")
        self.assertEqual(portindex.source_dir("https://distfiles.macports.org/ports.tar.gz", db),
                         db + "/sources/distfiles.macports.org/ports")
        self.assertEqual(portindex.source_dir("rsync://rsync.macports.org/macports/release/ports/", db),
                         db + "/sources/rsync.macports.org/macports/release")
        self.assertEqual(portindex.source_dir("file:///Users/alice/ports/", db), "/Users/alice/ports")

    def test_index_path_of_an_instance(self):
        prefix = make_prefix(self.path("opt", "local"))
        write_sources_conf(prefix, "rsync://rsync.macports.org/macports/release/tarballs/ports.tar [default]\n")
        inst = make_instance(Manager.PORTS, prefix=prefix, portdbpath=os.path.join(prefix, "var", "macports"))
        self.assertEqual(portindex.index_path(inst, {"HOME": self.path("home")}),
                         os.path.join(prefix, "var", "macports", "sources", "rsync.macports.org", "macports",
                                      "release", "tarballs", "ports", "PortIndex"))
        self.assertIsNone(portindex.load_for(inst, {"HOME": self.path("home")}))

    def synced(self):
        """Make a synced prefix: a default rsync source and the fixture PortIndex in its tree

        @returns  the MacPorts instance and the source's URL
        """
        prefix = make_prefix(self.path("opt", "local"))
        url = "rsync://rsync.macports.org/macports/release/tarballs/ports.tar"
        write_sources_conf(prefix, url + " [default]\n")
        inst = make_instance(Manager.PORTS, prefix=prefix, portdbpath=os.path.join(prefix, "var", "macports"))
        path = portindex.index_path(inst, {"HOME": self.path("home")})
        assert path is not None
        write_portindex(os.path.dirname(path))
        return inst, url

    @unittest.skipUnless(tkinter_available(), "tkinter is not available")
    def test_load_for_an_instance(self):
        inst, url = self.synced()
        index = PortIndex.load(inst, {"HOME": self.path("home")})
        assert index is not None
        self.assertEqual(index.source, url)
        entry = index.get("imagemagick")
        assert entry is not None
        self.assertEqual(entry.name, "ImageMagick")

    @unittest.skipIf(tkinter_available(), "tkinter is available")
    def test_load_without_tcl_says_so(self):
        inst, _ = self.synced()
        with self.assertRaises(PortIndexError):
            portindex.load_for(inst, {"HOME": self.path("home")})


class ReaderTest(TempDirTest):
    """The header and UTF-16 unit readers and the quick index, against the fixture PortIndex"""

    def setUp(self):
        super().setUp()
        self.index = write_portindex(self.path("ports"))
        self.entries = portindex_entries()
        with open(self.index + ".quick", encoding="utf-8") as fh:
            words = fh.read().split()
        self.offsets = dict(zip(words[::2], map(int, words[1::2])))

    def test_fixture_tells_units_from_bytes_and_characters(self):
        text = dict(self.entries)["fortune-emoji"]
        self.assertGreaterEqual(sum(1 for c in text if 0x7F < ord(c) <= 0xFFFF), 2)
        self.assertTrue(any(ord(c) > 0xFFFF for c in text))
        self.assertIn("\\{", text)
        units = utf16_units(text)
        self.assertNotEqual(units, len(text.encode("utf-8")))
        self.assertNotEqual(units, len(text))

    def test_read_entry_counts_utf16_units(self):
        with open(self.index, "rb") as fh:
            for name, text in self.entries:
                with self.subTest(name=name):
                    self.assertEqual(portindex.read_entry(fh, self.offsets[name.lower()]), (name, text))

    def test_byte_and_character_readers_would_fail(self):
        with open(self.index, "rb") as fh:
            fh.seek(self.offsets["fortune-emoji"])
            _, length = portindex.read_header(fh)
            start = fh.tell()
            by_bytes = fh.read(length - 1).decode("utf-8", "replace")
            fh.seek(start)
            by_chars = fh.read().decode("utf-8")[:length - 1]
        expected = dict(self.entries)["fortune-emoji"]
        self.assertNotEqual(by_bytes, expected)
        self.assertNotEqual(by_chars, expected)

    def test_read_units_reports_bytes_and_refuses_a_split_pair(self):
        data = "a😀b".encode("utf-8")
        self.assertEqual(portindex.read_units(io.BytesIO(data), 4), ("a😀b", 6))
        with self.assertRaises(PortIndexError):
            portindex.read_units(io.BytesIO(data), 2)
        with self.assertRaises(PortIndexError):
            portindex.read_units(io.BytesIO(b"ab"), 3)
        surrogates = b"x\xed\xa0\xbd\xed\xb8\x80"     # U+1F600 written as two 3-byte surrogates
        self.assertEqual(portindex.read_units(io.BytesIO(surrogates), 3), ("x" + chr(0xD83D) + chr(0xDE00), 7))

    def test_quick_index_and_scan_agree(self):
        self.assertEqual(portindex.read_quick(self.index), self.offsets)
        self.assertEqual(portindex.scan_offsets(self.index), self.offsets)
        self.assertIsNone(portindex.read_quick(self.path("nothing")))

    def test_bad_header(self):
        with self.assertRaises(PortIndexError):
            portindex.read_header(io.BytesIO(b"name 12 extra\n"))
        with self.assertRaises(PortIndexError):
            portindex.read_header(io.BytesIO(b"name 12"))


class TestSplitterParserTest(TempDirTest):
    """PortIndex lookups with the tests' own Tcl list splitter; `TkinterParserTest` runs them with Tcl's own"""

    def splitlist(self):
        """Supply the tests' own Tcl list splitter

        @returns  `tcl_splitlist`
        """
        return tcl_splitlist

    def index(self, quick=True, entries=None):
        """Write a PortIndex and open it with the class's splitter

        @param quick    write `PortIndex.quick` too
        @param entries  the `(name, entry)` pairs; None for the fixture's
        @returns        the PortIndex
        """
        return PortIndex(write_portindex(self.path("ports"), entries=entries, quick=quick),
                         splitlist=self.splitlist(), source="rsync://example.org/ports.tar")

    def test_lookup_is_case_insensitive(self):
        index = self.index()
        for name in ("ImageMagick", "imagemagick", "IMAGEMAGICK"):
            entry = index.get(name)
            self.assertEqual((entry.name, entry.version, entry.revision, entry.epoch),
                             ("ImageMagick", "6.9.13-38", 2, 1))
        self.assertTrue(index.has("imageMAGICK"))
        self.assertIsNone(index.get("graphicsmagick"))
        self.assertFalse(index.has("graphicsmagick"))

    def test_fields(self):
        entry = self.index().get("ImageMagick")
        self.assertEqual(entry.variants, ["x11", "universal"])
        self.assertEqual(entry.depends_lib, ["port:bzip2", "port:libpng", "port:zlib"])
        self.assertEqual(entry.depends_build, ["port:pkgconfig", "port:autoconf"])
        self.assertEqual((entry.homepage, entry.portdir, entry.platforms), ("https://imagemagick.org/",
                                                                           "graphics/ImageMagick", ["darwin"]))
        self.assertEqual(entry.description, "Tools and libraries to manipulate images in many formats")
        self.assertEqual(dict(entry.raw)["long_description"], "ImageMagick converts images; see \\{ its documentation")
        self.assertIsNone(entry.replaced_by)

    def test_multibyte_astral_and_escaped_brace(self):
        entry = self.index().get("fortune-emoji")
        self.assertEqual(entry.description, "Café naïve \U0001F600 { open")
        self.assertEqual((entry.version, entry.revision), ("3.24.0", 1))

    def test_replaced_by_and_pypi_homepage(self):
        index = self.index()
        self.assertEqual(index.get("gnome-themes-standard").replaced_by, "adwaita-icon-theme")
        found = index.by_homepage("HTTPS://pypi.org/project/requests")
        self.assertEqual([e.name for e in found], ["py313-requests"])
        self.assertEqual(found[0].platforms, ["darwin any"])
        self.assertEqual(index.by_homepage("https://pypi.org/project/numpy/"), [])

    def test_names_as_spelled(self):
        self.assertEqual(sorted(self.index().names()),
                         ["ImageMagick", "fortune-emoji", "gnome-themes-standard", "py313-requests"])

    def test_without_a_quick_index_the_headers_are_scanned(self):
        index = self.index(quick=False)
        self.assertEqual(index.get("PY313-requests").version, "2.32.5")

    def test_stale_quick_offset_falls_back_to_a_scan(self):
        index = self.index()
        with open(index.path + ".quick", "w", encoding="utf-8") as fh:
            fh.write("imagemagick 0\nfortune-emoji 0\n")
        stale = PortIndex(index.path, splitlist=self.splitlist())
        emoji, magick = stale.get("fortune-emoji"), stale.get("ImageMagick")
        assert emoji is not None and magick is not None
        self.assertEqual((emoji.version, magick.version), ("3.24.0", "6.9.13-38"))

    def test_malformed_entry_reads_as_absent(self):
        index = self.index(entries=[("broken", "name broken description {unbalanced"), ("ok", "name ok version 1")])
        self.assertIsNone(index.get("broken"))
        self.assertEqual(index.get("ok").version, "1")


@unittest.skipUnless(tkinter_available(), "tkinter is not available")
class TkinterParserTest(TestSplitterParserTest):
    """The lookups again with Tcl's own list splitter, and the tests' splitter against it"""

    def splitlist(self):
        """Supply no splitter, so that the PortIndex splits with Tcl's own"""
        return None

    def test_tcl_splitlist_matches_the_test_splitter(self):
        assert portindex.tkinter is not None
        tcl = portindex.tkinter.Tcl()
        for _, text in portindex_entries():
            with self.subTest(text=text[:40]):
                self.assertEqual(tuple(tcl.splitlist(text)), tcl_splitlist(text))


class TestSplitterTest(unittest.TestCase):
    """The tests' own Tcl list splitter on its own: escapes, nested braces and an unmatched brace"""

    def test_splitter(self):
        self.assertEqual(tcl_splitlist("a {b {c d}} e\\ f \\{"), ("a", "b {c d}", "e f", "{"))
        with self.assertRaises(ValueError):
            tcl_splitlist("a {b")


if __name__ == "__main__":
    unittest.main()

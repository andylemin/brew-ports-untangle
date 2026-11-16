"""The PortIndex reader

Per port, a `name length` header line, then a Tcl list of `length` UTF-16 code units (Tcl's `string length`,
newline included); `PortIndex.quick` maps names to header offsets.
"""

from __future__ import annotations

import codecs
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from types import ModuleType
from typing import BinaryIO

from ..model import Instance
from . import locate

tkinter: ModuleType | None
try:
    import tkinter
    _TKINTER_ERROR = ""
except ImportError as exc:      # a Python without Tk: PortIndex.load raises PortIndexError
    tkinter = None
    _TKINTER_ERROR = str(exc)

CHUNK = 65536
Splitter = Callable[[str], Sequence[str]]

_COMMENT_RE = re.compile(r"^\s*#|^$")
_SOURCE_RE = re.compile(r"^([\w-]+://\S+)(?:\s+\[(\w+(?:,\w+)*)\])?$")
_SNAPSHOT_RE = re.compile(r"^((?:https?|ftp|rsync)://.+/)(.+\.(tar\.gz|tar\.bz2|tar))$")
_ASTRAL = re.compile("[\U00010000-\U0010FFFF]")
_SURROGATE = re.compile("[\ud800-\udfff]")


class PortIndexError(Exception):
    """The PortIndex cannot be read: a cut entry, a bad header, or no Tcl to split entries with"""


# Sources ------------------------------------------------------------------------

def parse_sources(text: str) -> list[tuple[str, list[str]]]:
    """Parse the `<url> [flag,flag]` lines of sources.conf as base reads them

    @param text  the text of sources.conf
    @returns     the URL and flags of each source line, in file order
    """
    out = []
    for line in text.splitlines():
        line = line.rstrip()
        if _COMMENT_RE.match(line):
            continue
        match = _SOURCE_RE.match(line)
        if match:
            out.append((match.group(1), match.group(2).split(",") if match.group(2) else []))
    return out


def default_source(sources_conf: str) -> str | None:
    """Return the `[default]` source of sources.conf; without one, the last source, as base uses

    @param sources_conf  the path of sources.conf
    @returns             the source's URL; None when the file cannot be read or names no source
    """
    try:
        with open(sources_conf, encoding="utf-8", errors="replace") as fh:
            sources = parse_sources(fh.read())
    except OSError:
        return None
    chosen = None
    for url, flags in sources:
        if "default" in flags:
            chosen = url
    if chosen is None and sources:
        chosen = sources[-1][0]
    return chosen


def source_dir(url: str, portdbpath: str) -> str:
    """Return the directory of a source's tree, as `macports::getsourcepath` computes it

    A tarball source is `<portdbpath>/sources/<host>/<path without the archive>/ports`, another URL
    `<portdbpath>/sources/<host>/<first>/<second>`, and a `file://` source its own path.

    @param url         the source's URL
    @param portdbpath  the instance's `portdbpath`
    @returns           the directory
    """
    if url.startswith("file://"):
        return os.path.normpath(url[len("file://"):])
    parts = re.split(r"[:/]", url)
    if _SNAPSHOT_RE.match(url):
        return os.path.join(portdbpath, "sources", *[p for p in parts[3:-1] if p], "ports")
    return os.path.join(portdbpath, "sources", *[p for p in parts[3:6] if p])


def _default_index(instance: Instance, environ: Mapping[str, str]) -> tuple[str | None, str | None]:
    """Return the default source's URL and its `PortIndex` path

    @param instance  the MacPorts instance
    @param environ   the environment, whose `HOME` holds the user's macports.conf
    @returns         the URL, None without a source; the path, None without a source or a `portdbpath`
    """
    config = locate.read_config(instance.prefix, environ)
    url = default_source(config["sources_conf"])
    if url is None or not instance.portdbpath:
        return url, None
    return url, os.path.join(source_dir(url, instance.portdbpath), "PortIndex")


def index_path(instance: Instance, environ: Mapping[str, str]) -> str | None:
    """Return `<tree of the default source>/PortIndex` of an instance, whether or not it exists

    @param instance  the MacPorts instance
    @param environ   the environment, whose `HOME` holds the user's macports.conf
    @returns         the path; None without a default source or a `portdbpath`
    """
    return _default_index(instance, environ)[1]


# Reading --------------------------------------------------------------------------

def read_units(fh: BinaryIO, units: int) -> tuple[str, int]:
    """Read `units` UTF-16 code units of UTF-8 text from `fh`

    A character above U+FFFF counts two units, as in Tcl's `string length`, and a surrogate written as
    three bytes one; a unit takes at most three bytes, so no read goes far past the entry.

    @param fh               the PortIndex, at the first byte of the text
    @param units            the number of units to read
    @returns                the text, and the number of bytes it took
    @throws PortIndexError  the file ends inside the text, or `units` ends inside a character
    """
    decoder = codecs.getincrementaldecoder("utf-8")(errors="surrogatepass")
    out: list[str] = []
    count = 0
    while count < units:
        chunk = fh.read(min(CHUNK, max(16, 3 * (units - count))))
        if not chunk:
            raise PortIndexError("the PortIndex ends inside an entry")
        text = decoder.decode(chunk)
        i = 0
        while i < len(text) and count < units:
            piece = text[i:i + units - count]
            astral = _ASTRAL.search(piece)
            end = len(piece) if astral is None else astral.start()
            out.append(piece[:end])
            count += end
            i += end
            if astral is not None:
                out.append(piece[end])
                count += 2
                i += 1
    if count != units:
        raise PortIndexError("an entry length ends inside a character")
    result = "".join(out)
    return result, len(result.encode("utf-8", "surrogatepass"))


def read_header(fh: BinaryIO) -> tuple[str, int]:
    """Read the `name length` line before an entry

    @param fh               the PortIndex, at the start of a header line
    @returns                the port's name without its braces, and the entry's length in units
    @throws PortIndexError  the line is not a header
    """
    line = fh.readline()
    parts = line.decode("utf-8", "replace").split()
    if not line.endswith(b"\n") or len(parts) != 2 or not parts[1].isdigit():
        raise PortIndexError(f"not a PortIndex header: {line[:200]!r}")
    name = parts[0]
    if len(name) > 1 and name.startswith("{") and name.endswith("}"):
        name = name[1:-1]
    return name, int(parts[1])


def read_entry(fh: BinaryIO, offset: int) -> tuple[str, str]:
    """Read the header at `offset` and the `length - 1` units of the entry after it (its newline left out)

    @param fh               the PortIndex
    @param offset           the byte offset of the header
    @returns                the port's name and the entry's text
    @throws PortIndexError  a bad header, or the file ends inside the entry
    """
    fh.seek(offset)
    name, length = read_header(fh)
    text, _ = read_units(fh, length - 1)
    return name, text


def read_quick(index: str) -> dict[str, int] | None:
    """Read `PortIndex.quick`: `<lower-cased name> <byte offset>` pairs

    @param index  the PortIndex's path
    @returns      the byte offset of each lower-cased name; None when the file is absent or malformed
    """
    try:
        with open(index + ".quick", encoding="utf-8", errors="replace") as fh:
            words = fh.read().split()
    except OSError:
        return None
    if len(words) % 2 or not all(w.isdigit() for w in words[1::2]):
        return None
    return {name: int(offset) for name, offset in zip(words[::2], words[1::2])}


def scan_offsets(index: str) -> dict[str, int]:
    """Build a quick index by reading every header, as `mports_generate_quickindex` does

    A line that is no header is skipped, and a later entry of a name wins.

    @param index            the PortIndex's path
    @returns                the byte offset of each lower-cased name's header
    @throws OSError         the file cannot be read
    @throws PortIndexError  the file ends inside an entry
    """
    out: dict[str, int] = {}
    with open(index, "rb") as fh:
        offset = 0
        while True:
            fh.seek(offset)
            line = fh.readline()
            if not line:
                return out
            fh.seek(offset)
            try:
                name, length = read_header(fh)
            except PortIndexError:
                offset += len(line)
                continue
            _, size = read_units(fh, length)
            out[name.lower()] = offset
            offset += len(line) + size


# Entries -------------------------------------------------------------------------

@dataclass
class PortEntry:
    """One PortIndex entry; `raw` keeps every key-value pair in file order"""

    name: str
    version: str | None
    revision: int = 0
    epoch: int = 0
    homepage: str | None = None
    description: str | None = None
    replaced_by: str | None = None
    variants: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    depends_lib: list[str] = field(default_factory=list)
    depends_run: list[str] = field(default_factory=list)
    depends_build: list[str] = field(default_factory=list)
    subports: list[str] = field(default_factory=list)
    portdir: str | None = None
    raw: list[tuple[str, str]] = field(default_factory=list)


def _join_surrogates(text: str) -> str:
    """Join surrogate pairs that came back as two characters into one

    @param text  the text
    @returns     the text with each surrogate pair one character
    """
    if _SURROGATE.search(text):
        return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    return text


def _number(value: str | None) -> int:
    """Return a number field of an entry as an int

    @param value  the field's text, or None
    @returns      the number; 0 for None or a text that is no number
    """
    try:
        return int(value or 0)
    except ValueError:
        return 0


def _homepage_key(url: str) -> str:
    """Return the key that homepages match by, case and a trailing `/` ignored

    @param url  the homepage
    @returns    the key
    """
    return url.strip().rstrip("/").lower()


class PortIndex:
    """Case-insensitive lookups in one PortIndex file; `splitlist` defaults to Tcl's own list parser

    A missing `.quick`, or an offset that does not lead to the name (a stale `.quick`), falls back
    to reading every header once.
    """

    def __init__(self, path: str, splitlist: Splitter | None = None, source: str | None = None) -> None:
        """Read nothing yet: the offsets and the entries are read on first use

        @param path       the PortIndex's path
        @param splitlist  the Tcl list splitter; None for Tcl's own through tkinter
        @param source     the URL of the source the PortIndex belongs to
        """
        self.path = path
        self.source = source
        self._split = splitlist
        self._errors: tuple[type[Exception], ...] = (ValueError,)
        self._offsets: dict[str, int] | None = None
        self._scanned = False
        self._cache: dict[str, PortEntry | None] = {}
        self._homepages: dict[str, list[str]] | None = None

    @classmethod
    def load(cls, instance: Instance, environ: Mapping[str, str]) -> "PortIndex" | None:
        """Load the PortIndex of the instance's default source

        It raises `PortIndexError` when the file exists but Tcl is unavailable.

        @param instance  the MacPorts instance
        @param environ   the environment, whose `HOME` holds the user's macports.conf
        @returns         the PortIndex; None when the tree has never been synced
        """
        url, path = _default_index(instance, environ)
        if path is None or not os.path.isfile(path):
            return None
        index = cls(path, source=url)
        index._splitter()
        return index

    def _splitter(self) -> Splitter:
        """Return the list splitter, by default Tcl's own `splitlist` through tkinter

        @returns                the splitter
        @throws PortIndexError  Tcl is unavailable
        """
        if self._split is None:
            try:
                if tkinter is None:
                    raise ImportError(_TKINTER_ERROR)
                self._split = tkinter.Tcl().splitlist
                self._errors = (tkinter.TclError, ValueError)
            except Exception as exc:  # Tcl through tkinter can fail in any way: ImportError, TclError, RuntimeError
                raise PortIndexError(f"Tcl is unavailable to read the PortIndex: {exc}") from None
        return self._split

    def _quick(self) -> dict[str, int]:
        """Return the header offsets, read once from `.quick` or else from a scan of every header

        @returns  the byte offset of each lower-cased name
        """
        if self._offsets is None:
            offsets = read_quick(self.path)
            if offsets is None:
                offsets = self._scan()
            self._offsets = offsets
        return self._offsets

    def _scan(self) -> dict[str, int]:
        """Return the header offsets that reading every header finds, and mark the scan as done

        @returns  the byte offset of each lower-cased name; empty when the file cannot be read
        """
        self._scanned = True
        try:
            return scan_offsets(self.path)
        except (OSError, PortIndexError):
            return {}

    def has(self, name: str) -> bool:
        """Return whether the PortIndex holds a port, matched without regard to case

        @param name  the port's name
        @returns     True when the header offsets name it
        """
        return name.lower() in self._quick()

    def get(self, name: str) -> PortEntry | None:
        """Return the entry of a port, matched without regard to case and read once

        @param name  the port's name
        @returns     the entry; None when the PortIndex holds none or cannot split it
        """
        key = name.lower()
        if key not in self._cache:
            self._cache[key] = self._lookup(key)
        return self._cache[key]

    def _lookup(self, key: str) -> PortEntry | None:
        """Read and parse the entry of a name; an offset that leads elsewhere scans every header once

        @param key  the lower-cased name
        @returns    the entry, or None
        """
        offset = self._quick().get(key)
        if offset is None:
            return None
        try:
            with open(self.path, "rb") as fh:
                found, text = read_entry(fh, offset)
        except (OSError, PortIndexError):
            found, text = "", ""
        if found.lower() != key:
            if self._scanned:
                return None
            self._offsets = self._scan()
            return self._lookup(key)
        return self.parse(found, text)

    def parse(self, name: str, text: str) -> PortEntry | None:
        """Parse an entry's key-value list

        @param name             the port's name in the header, kept when the entry names none
        @param text             the entry's Tcl list
        @returns                the entry; None when the list cannot be split or holds an odd number of words
        @throws PortIndexError  Tcl is unavailable
        """
        split = self._splitter()
        try:
            words = [_join_surrogates(w) for w in split(_join_surrogates(text))]
        except self._errors:
            return None
        if len(words) % 2:
            return None
        pairs = list(zip(words[::2], words[1::2]))
        fields = dict(pairs)

        def items(key: str) -> list[str]:
            value = fields.get(key)
            if not value:
                return []
            try:
                return [_join_surrogates(v) for v in split(value)]
            except self._errors:
                return [value]

        def text_of(key: str) -> str | None:
            value = (fields.get(key) or "").strip()
            return value or None

        description = fields.get("description")
        if description is not None:
            try:
                description = " ".join(_join_surrogates(w) for w in split(description))   # as `port info` prints it
            except self._errors:
                pass
        return PortEntry(name=fields.get("name") or name, version=text_of("version"),
                         revision=_number(fields.get("revision")), epoch=_number(fields.get("epoch")),
                         homepage=text_of("homepage"), description=description or None,
                         replaced_by=text_of("replaced_by"), variants=items("variants"),
                         platforms=items("platforms"), categories=items("categories"),
                         depends_lib=items("depends_lib"), depends_run=items("depends_run"),
                         depends_build=items("depends_build"), subports=items("subports"),
                         portdir=text_of("portdir"), raw=pairs)

    def names(self) -> list[str]:
        """Return every port name as the PortIndex spells it

        @returns  the names, in the order of their lower-cased spellings
        """
        out = []
        with open(self.path, "rb") as fh:
            for _, offset in sorted(self._quick().items()):
                fh.seek(offset)
                try:
                    out.append(read_header(fh)[0])
                except PortIndexError:
                    continue
        return out

    def by_homepage(self, url: str) -> list[PortEntry]:
        """Return the entries whose homepage is `url`, case and a trailing `/` ignored

        Python ports carry `https://pypi.org/project/<pypi name>/`. The homepage index is built once.

        @param url  the homepage
        @returns    the entries, in file order
        """
        if self._homepages is None:
            self._homepages = {}
            with open(self.path, "rb") as fh:
                for _, offset in sorted(self._quick().items(), key=lambda kv: kv[1]):
                    try:
                        name, text = read_entry(fh, offset)
                    except PortIndexError:
                        continue
                    entry = self.parse(name, text)
                    if entry is not None and entry.homepage:
                        self._homepages.setdefault(_homepage_key(entry.homepage), []).append(name.lower())
        found = (self.get(key) for key in self._homepages.get(_homepage_key(url), []))
        return [entry for entry in found if entry is not None]


def load_for(instance: Instance, environ: Mapping[str, str]) -> PortIndex | None:
    """Load the PortIndex of the instance's default source (`PortIndex.load`)

    @param instance         the MacPorts instance
    @param environ          the environment, whose `HOME` holds the user's macports.conf
    @returns                the PortIndex; None when the tree has never been synced
    @throws PortIndexError  the file exists but Tcl is unavailable
    """
    return PortIndex.load(instance, environ)

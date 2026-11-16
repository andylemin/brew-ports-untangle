"""Builders for the MacPorts tests: registries, prefixes and PortIndex files in a test's temporary directory

Beside them, a stand-in PortIndex and a Tcl list splitter for hosts without tkinter.
"""

from __future__ import annotations

import io
import os
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from brew_ports import report, runner as runner_mod
from brew_ports.macports import registry
from brew_ports.macports.portindex import PortEntry, PortIndex, PortIndexError

HERE = os.path.dirname(os.path.abspath(__file__))
FILE_COLUMNS = ("id", "path", "actual_path", "active", "binary")


def fixture(name: str) -> str:
    """Return the path of a file in the MacPorts fixtures directory

    @param name  the file's name
    @returns     the file's path
    """
    return os.path.join(HERE, name)


def read_fixture(name: str) -> str:
    """Return the text of a file in the MacPorts fixtures directory

    @param name  the file's name
    @returns     the file's text
    """
    with open(fixture(name), encoding="utf-8") as fh:
        return fh.read()


class QuietConsole(report.Console):
    """A console that writes into memory, so a test prints nothing"""

    def __init__(self) -> None:
        """Write both streams into `io.StringIO` buffers"""
        super().__init__(stream=io.StringIO(), err=io.StringIO())


def fake_runner(tmp: str, responses: Mapping[Sequence[str], Any] | None = None, *, home: str = "/Users/alice",
                host_arch: str = "arm64", default: runner_mod.FakeResponse | None = None,
                run_dir=None) -> runner_mod.FakeRunner:
    """Build a FakeRunner whose unknown commands fail with exit 1 unless `default` says otherwise

    @param tmp        the test's temporary directory, which holds the outputs without a run directory
    @param responses  the canned responses, keyed by argv
    @param home       the `HOME` of the runner's environment
    @param host_arch  the host's architecture
    @param default    the response to a command without one; None for exit 1
    @param run_dir    the run directory that holds the outputs; None for `<tmp>/out`
    @returns          the runner
    """
    return runner_mod.FakeRunner(
        responses=responses or {}, default=default or runner_mod.FakeResponse(exit=1), console=QuietConsole(),
        environ={"HOME": home, "USER": "alice"}, host_arch=host_arch, run_dir=run_dir,
        out_dir=None if run_dir is not None else os.path.join(tmp, "out"))


# Registries ---------------------------------------------------------------------

def port(port_id: int, name: str, version: str, revision: int = 0, **kw: Any) -> dict[str, Any]:
    """Build a `ports` row; keys the schema lacks are dropped when it is inserted

    @param port_id   the row's `id`
    @param name      the port's name
    @param version   the port's version
    @param revision  the port's revision
    @param kw        further columns, which override the defaults
    @returns         the row, by column
    """
    row: dict[str, Any] = {
        "id": port_id, "name": name, "version": version, "revision": revision, "epoch": 0, "variants": "",
        "requested_variants": "", "negated_variants": "", "state": "installed", "requested": 1,
        "os_platform": "darwin", "os_major": 25, "archs": "arm64", "location": None, "date": 1700000000,
        "installtype": "image", "portfile": "", "cxx_stdlib": "libc++", "cxx_stdlib_overridden": 0}
    row.update(kw)
    return row


def _insert(conn: sqlite3.Connection, table: str, rows: Iterable[Mapping[str, Any]]) -> None:
    """Insert rows into a table, each with only the keys the table has columns for

    @param conn   the registry connection
    @param table  the table's name
    @param rows   the rows, by column
    """
    columns = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    for row in rows:
        keys = [k for k in row if k in columns]
        conn.execute(f"INSERT INTO {table} ({', '.join(keys)}) VALUES ({', '.join('?' * len(keys))})",
                     [row[k] for k in keys])


def make_registry(portdbpath: str, *, schema: str = "1.215", ports: Sequence[Mapping[str, Any]] = (),
                  files: Sequence[Sequence[Any]] = (), deps: Sequence[tuple[int, str]] = (),
                  snapshots: Sequence[tuple[int, str]] = (), journal: str = "wal") -> str:
    """Create `<portdbpath>/registry/registry.db` from a schema fixture and rows

    @param portdbpath  the instance's `portdbpath`
    @param schema      the schema version, which names the `schema-<version>.sql` fixture
    @param ports       the `ports` rows, as `port` builds them
    @param files       the `files` rows, `(id, path, actual_path, active, binary)` tuples
    @param deps        the `dependencies` rows, `(id, name)` pairs
    @param snapshots   the `snapshots` rows, `(id, note)` pairs
    @param journal     the journal mode, such as `wal` or `delete`
    @returns           the path of `registry.db`
    """
    directory = os.path.join(portdbpath, "registry")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "registry.db")
    conn = sqlite3.connect(path)
    try:
        conn.create_collation("VERSION", registry.vercmp)
        conn.execute(f"PRAGMA journal_mode={journal}")
        conn.executescript(read_fixture(f"schema-{schema}.sql"))
        _insert(conn, "ports", ports)
        _insert(conn, "files", [dict(zip(FILE_COLUMNS, f)) for f in files])
        _insert(conn, "dependencies", [{"id": i, "name": n} for i, n in deps])
        _insert(conn, "snapshots", [{"id": i, "note": n} for i, n in snapshots])
        conn.commit()
    finally:
        conn.close()
    return path


def count_rows(path: str, table: str = "ports") -> int:
    """Count the rows of one table of a registry file

    @param path   the registry file
    @param table  the table's name
    @returns      the number of rows
    """
    conn = sqlite3.connect(path)
    try:
        conn.create_collation("VERSION", registry.vercmp)
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


# Prefixes -----------------------------------------------------------------------

def write(path: str, text: str = "", mode: int = 0o644) -> str:
    """Write a text file with a mode, making its parent directories

    @param path  the file
    @param text  the file's content
    @param mode  the file's permission bits
    @returns     the path
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, mode)
    return path


def make_prefix(prefix: str, *, version: str | None = "2.12.7", os_platform: str | None = "darwin",
                os_major: str | None = "25", binary: bool = True, tclsh: bool = True,
                conf: Mapping[str, str] | None = None) -> str:
    """Make a MacPorts prefix with base's markers: macports.conf, macports_autoconf.tcl, bin/port and tclsh8.6

    Base's tclsh8.6 is an empty stand-in; the tests fake `lipo`.

    @param prefix       the prefix to make
    @param version      the `macports_version` of macports_autoconf.tcl; None leaves it out
    @param os_platform  the `os_platform` base is built for; None leaves it out
    @param os_major     the `os_major` base is built for; None leaves it out
    @param binary       write `bin/port`
    @param tclsh        write base's `tclsh8.6`
    @param conf         the macports.conf settings; None for `prefix`, `portdbpath` and `applications_dir`
    @returns            the prefix
    """
    settings = conf if conf is not None else {
        "prefix": prefix, "portdbpath": os.path.join(prefix, "var", "macports"),
        "applications_dir": "/Applications/MacPorts"}
    write(os.path.join(prefix, "etc", "macports", "macports.conf"),
          "# MacPorts system-wide configuration file\n"
          + "".join(f"{key!s:<20}{value}\n" for key, value in settings.items()))
    variables = [("macports_conf_path", os.path.join(prefix, "etc", "macports")), ("macports_version", version),
                 ("os_platform", os_platform), ("os_major", os_major)]
    write(os.path.join(prefix, "libexec", "macports", "lib", "macports1.0", "macports_autoconf.tcl"),
          "package provide macports 1.0\n\nnamespace eval macports::autoconf {\n"
          + "".join(f'    variable {k} "{v}"\n' for k, v in variables if v is not None) + "}\n")
    if binary:
        write(os.path.join(prefix, "bin", "port"), "#!/bin/sh\nexit 0\n", 0o755)
    if tclsh:
        write(os.path.join(prefix, "libexec", "macports", "bin", "tclsh8.6"), "", 0o755)
    os.makedirs(os.path.join(prefix, "var", "macports"), exist_ok=True)
    return prefix


def write_sources_conf(prefix: str, lines: str) -> str:
    """Write the prefix's `etc/macports/sources.conf`

    @param prefix  the MacPorts prefix
    @param lines   the file's text
    @returns       the file's path
    """
    return write(os.path.join(prefix, "etc", "macports", "sources.conf"), lines)


# PortIndex ----------------------------------------------------------------------

def utf16_units(text: str) -> int:
    """Count UTF-16 code units, as Tcl's `string length` does

    @param text  the text
    @returns     the number of units, two for a character above U+FFFF
    """
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def portindex_entries() -> list[tuple[str, str]]:
    """Return the fixture's `(name, entry)` pairs: one entry per line, its name first

    @returns  the pairs, in fixture order
    """
    out = []
    for line in read_fixture("portindex-entries.txt").splitlines():
        if line.strip():
            name, _, text = line.partition(" ")
            out.append((name, text))
    return out


def write_portindex(directory: str, entries: Sequence[tuple[str, str]] | None = None, quick: bool = True) -> str:
    """Write a PortIndex as `portindex` does, with its `.quick` of byte offsets

    Each entry follows a `[list $name $len]` line and ends in a newline, `len` being its `string length` plus one.

    @param directory  the PortIndex's directory, made when missing
    @param entries    the `(name, entry)` pairs; None for the fixture's
    @param quick      write `PortIndex.quick` too
    @returns          the PortIndex's path
    """
    entries = portindex_entries() if entries is None else entries
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "PortIndex")
    offsets = []
    with open(path, "wb") as fh:
        for name, text in entries:
            offsets.append((name.lower(), fh.tell()))
            fh.write(f"{name} {utf16_units(text) + 1}\n".encode("utf-8"))
            fh.write(text.encode("utf-8") + b"\n")
    if quick:
        with open(path + ".quick", "w", encoding="utf-8") as fh:
            fh.write("".join(f"{key} {offset}\n" for key, offset in offsets))
    return path


_SPACE = " \t\n\r\f\v"
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}


def tcl_splitlist(text: str) -> tuple[str, ...]:
    """Split a Tcl list on hosts without tkinter: bare words with backslash escapes, and brace groups

    A backslash-escaped brace does not count, and the content of a group stays literal.

    @param text         the list
    @returns            the elements
    @throws ValueError  an unmatched open brace, or a brace group with characters right after it
    """
    out: list[str] = []
    i, n = 0, len(text)
    while True:
        while i < n and text[i] in _SPACE:
            i += 1
        if i >= n:
            return tuple(out)
        if text[i] == "{":
            depth, j = 1, i + 1
            while j < n and depth:
                if text[j] == "\\":
                    j += 2
                    continue
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            if depth:
                raise ValueError("unmatched open brace in list")
            if j < n and text[j] not in _SPACE:
                raise ValueError("list element in braces followed by characters")
            out.append(text[i + 1:j - 1])
            i = j
        else:
            word = []
            while i < n and text[i] not in _SPACE:
                if text[i] == "\\" and i + 1 < n:
                    word.append(_ESCAPES.get(text[i + 1], text[i + 1]))
                    i += 2
                else:
                    word.append(text[i])
                    i += 1
            out.append("".join(word))


def tkinter_available() -> bool:
    """Return whether Tcl can split PortIndex entries on this Python, as `PortIndex` itself finds out

    @returns  False when a `PortIndex` without a splitter of its own raises PortIndexError
    """
    try:
        PortIndex("").parse("", "")
    except PortIndexError:
        return False
    return True


class FakePortIndex:
    """A PortIndex stand-in holding `PortEntry` records"""

    def __init__(self, entries: Iterable[PortEntry],
                 source: str = "rsync://rsync.macports.org/macports/release/tarballs/ports.tar",
                 path: str = "/opt/local/var/macports/sources/rsync.macports.org/macports/release/tarballs/ports/"
                             "PortIndex"):
        """Index the entries by lower-cased name

        @param entries  the entries
        @param source   the source URL the index reports
        @param path     the PortIndex path the index reports
        """
        self.entries = {e.name.lower(): e for e in entries}
        self.source = source
        self.path = path

    def get(self, name: str) -> PortEntry | None:
        """Return the entry of a port, matched without regard to case

        @param name  the port's name
        @returns     the entry, or None
        """
        return self.entries.get(name.lower())

    def has(self, name: str) -> bool:
        """Return whether the index holds a port, matched without regard to case

        @param name  the port's name
        @returns     True when an entry has that name
        """
        return name.lower() in self.entries

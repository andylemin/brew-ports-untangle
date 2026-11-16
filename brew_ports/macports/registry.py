"""MacPorts registry access through SQLite backups, and base's version order

Every query runs on a copy taken with SQLite's online backup API, so a `port` writing meanwhile cannot tear it.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import string
import tempfile
import time
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# The busy timeout of each backup step; the deadline of `_backup` decides when
# a registry that makes no progress is busy.
BUSY_TIMEOUT_S = 5.0

REGISTRY_REL = os.path.join("registry", "registry.db")


class RegistryMissing(Exception):
    """registry.db does not exist"""


class RegistryBusy(Exception):
    """Another `port` process kept the registry from being copied"""


def _backup(src_uri: str, dest_path: str, wait_s: float) -> None:
    """Copy a database into `dest_path` with SQLite's online backup API, in one step

    One read transaction copies every page. Where the user cannot write the wal-index (`port` leaves a root's
    `-shm` behind), SQLite sees the file as changed at each read transaction, which would restart a backup
    taken step by step on every step.

    @param src_uri                    the source's `file:` URI
    @param dest_path                  the copy to write
    @param wait_s                     the seconds without a copied page after which the source is busy
    @throws sqlite3.OperationalError  the source cannot be opened or read
    @throws RegistryBusy              `wait_s` seconds pass without a copied page
    """
    deadline = time.monotonic() + wait_s

    def progress(status: int, _remaining: int, _total: int) -> None:
        # Called after every step. SQLITE_BUSY (5) and SQLITE_LOCKED (6) are
        # steps that copied nothing because a writer holds the database; any
        # other status copied pages and restarts the clock.
        nonlocal deadline
        if status not in (5, 6):
            deadline = time.monotonic() + wait_s
        elif time.monotonic() > deadline:
            raise RegistryBusy(f"no progress for {int(wait_s)} s: another port process holds the registry")

    src = sqlite3.connect(src_uri, uri=True, timeout=BUSY_TIMEOUT_S)
    try:
        dst = sqlite3.connect(dest_path)
        try:
            src.backup(dst, pages=-1, progress=progress)
        finally:
            dst.close()
    finally:
        src.close()


def _stamp(path: str) -> tuple[int, int] | None:
    """Return a file's size and modification time, which change when a writer touches it

    @param path  the file
    @returns     `(st_size, st_mtime_ns)`; None when the file does not exist
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    return (st.st_size, st.st_mtime_ns)


def backup_registry(portdbpath: str, dest_path: str, wait_s: float = 30.0) -> None:
    """Copy registry.db into `dest_path` through SQLite's online backup API, which restarts when a writer changes it

    The source opens read-only, so nothing is written beside it; one that cannot (a WAL database without
    its `-shm`, a hot `-journal`) is first copied with its `-wal` or `-journal` into a private directory.

    @param portdbpath              the instance's `portdbpath`
    @param dest_path               the copy to write
    @param wait_s                  the seconds without progress after which the registry is busy
    @throws RegistryMissing        registry.db does not exist
    @throws RegistryBusy           another `port` holds the registry, or it keeps changing while it is copied
    @throws sqlite3.DatabaseError  the registry cannot be read as a database
    @throws OSError                the user cannot read the registry
    """
    src_path = os.path.join(portdbpath, "registry", "registry.db")
    try:
        os.stat(src_path)            # PermissionError propagates: CANNOT_RUN
    except FileNotFoundError:
        raise RegistryMissing(src_path) from None
    try:
        _backup("file:" + urllib.parse.quote(src_path) + "?mode=ro", dest_path, wait_s)
        return
    except sqlite3.OperationalError as exc:
        if "unable to open" not in str(exc) and "readonly" not in str(exc):
            raise
    suffixes = ("", "-wal", "-journal", "-shm")
    for _ in range(3):
        private = tempfile.mkdtemp(prefix="brew-ports-registry-raw-")
        try:
            before = [_stamp(src_path + s) for s in suffixes]
            try:
                for suffix, stamp in zip(suffixes[:3], before[:3]):
                    if stamp is not None:
                        shutil.copy2(src_path + suffix, os.path.join(private, "registry.db" + suffix))
            except FileNotFoundError:
                pass                     # a file vanished mid-copy: copy again into a fresh directory
            else:
                if [_stamp(src_path + s) for s in suffixes] == before:
                    _backup("file:" + urllib.parse.quote(os.path.join(private, "registry.db")), dest_path, wait_s)
                    return
        finally:
            shutil.rmtree(private, ignore_errors=True)
        time.sleep(1.0)
    raise RegistryBusy("the registry kept changing while it was copied")


def _private_dir() -> tempfile.TemporaryDirectory:
    """Return a private directory for one registry copy, which its `Registry` removes on close

    @returns  the directory
    """
    return tempfile.TemporaryDirectory(prefix="brew-ports-registry-")


def open_registry_copy(portdbpath: str) -> tuple[sqlite3.Connection, tempfile.TemporaryDirectory]:
    """Open a fresh backup of the registry; the caller closes the connection and cleans up the directory

    @param portdbpath  the instance's `portdbpath`
    @returns           the connection, with the `VERSION` collation, and the copy's directory
    """
    tmp = _private_dir()
    dest = os.path.join(tmp.name, "registry.db")
    try:
        backup_registry(portdbpath, dest)
    except BaseException:
        tmp.cleanup()               # on failure only: after a success the caller owns the directory
        raise
    conn = sqlite3.connect(dest)
    conn.create_collation("VERSION", vercmp)
    conn.row_factory = sqlite3.Row
    return conn, tmp


# Version order: src/pextlib1.0/vercomp.c statement by statement, with
# ASCII-only character classes because the C code runs in the C locale.

_DIGITS = frozenset(string.digits)
_ALPHAS = frozenset(string.ascii_letters)


def _isdigit(c: str) -> bool:
    """Return whether a character is an ASCII digit, as `isdigit` in the C locale

    @param c  one character, or the empty string past the end
    @returns  True for 0 to 9
    """
    return c in _DIGITS


def _isalpha(c: str) -> bool:
    """Return whether a character is an ASCII letter, as `isalpha` in the C locale

    @param c  one character, or the empty string past the end
    @returns  True for a to z and A to Z
    """
    return c in _ALPHAS


def vercmp(a: str, b: str) -> int:
    """Compare two MacPorts version strings

    @param a  a version
    @param b  another version
    @returns  1 when `a` is the newer, -1 when `b` is, 0 when they are equal
    """
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la and j < lb:
        while i < la and not (_isdigit(a[i]) or _isalpha(a[i])):
            i += 1
        while j < lb and not (_isdigit(b[j]) or _isalpha(b[j])):
            j += 1
        ca = a[i] if i < la else ""
        cb = b[j] if j < lb else ""
        if not _isdigit(cb) and _isdigit(ca):
            return 1
        if (_isdigit(ca) and _isalpha(cb)) or (_isalpha(ca) and _isdigit(cb)):
            return -1
        ei, ej = i, j
        if _isalpha(ca):
            while ei < la and _isalpha(a[ei]):
                ei += 1
            while ej < lb and _isalpha(b[ej]):
                ej += 1
        else:
            while ei < la and _isdigit(a[ei]):
                ei += 1
            while ej < lb and _isdigit(b[ej]):
                ej += 1
            while i < ei and a[i] == "0":
                i += 1
            while j < ej and b[j] == "0":
                j += 1
            if ei - i > ej - j:
                return 1
            if ej - j > ei - i:
                return -1
        while i < ei and j < ej and a[i] == b[j]:
            i += 1
            j += 1
        if i < ei and j < ej:
            return 1 if a[i] > b[j] else -1
        i, j = ei, ej
    if i >= la and j >= lb:
        return 0
    return 1 if i < la else -1


# Rows ------------------------------------------------------------------------

_VARIANT_TOKEN = re.compile(r"[+-][^+-]+")


def split_variants(text: str | None) -> list[str]:
    """Split variants as base writes them: `+huge+python-x11` into `+huge`, `+python` and `-x11`

    @param text  the variants, or None
    @returns     the tokens, in order
    """
    return _VARIANT_TOKEN.findall(text or "")


def _int(value: Any, default: int = 0) -> int:
    """Return a column's value as an int

    @param value    the value, of any type
    @param default  the result for None or a value that is no number
    @returns        the number
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass
class PortRow:
    """One row of `ports`; a column the schema lacks reads as None"""

    id: int
    name: str
    version: str
    revision: int
    epoch: int
    variants: str
    state: str | None
    requested: bool | None
    os_platform: str | None
    os_major: str | None          # a number, or "any" for `platforms any` ports
    archs: str | None
    location: str | None
    date: Any
    requested_variants: str | None = None
    negated_variants: str | None = None
    cxx_stdlib: str | None = None
    cxx_stdlib_overridden: int | None = None

    @property
    def active(self) -> bool:
        """Return whether this version is the active one, its `state` being `installed`

        @returns  False for an `imaged` row
        """
        return self.state == "installed"

    @property
    def version_string(self) -> str:
        """Return `<version>_<revision><variants>`, as `port installed` prints it

        @returns  the version string
        """
        return f"{self.version}_{self.revision}{self.variants}"

    @property
    def spec_args(self) -> list[str]:
        """Return the two argv tokens that address one installed version

        @returns  the name and `@<version>_<revision><variants>`
        """
        return [self.name, "@" + self.version_string]

    @property
    def requested_variant_tokens(self) -> list[str]:
        """Return the user's `+x` and `-y` choices

        The `requested_variants` column holds them from schema 1.210; an older registry keeps only the
        `-x` tokens of its `negated_variants` column.

        @returns  the tokens, in order
        """
        if self.requested_variants is not None:
            return split_variants(self.requested_variants)
        return [t for t in split_variants(self.negated_variants) if t.startswith("-")]


def _port_row(data: Mapping[str, Any]) -> PortRow:
    """Return the row of `ports` that a query selected, with None for every column it lacks

    @param data  the selected columns, by name
    @returns     the row
    """
    requested = data.get("requested")
    os_major = data.get("os_major")
    overridden = data.get("cxx_stdlib_overridden")
    return PortRow(
        id=int(data["id"]), name=str(data["name"]), version=str(data.get("version") or ""),
        revision=_int(data.get("revision")), epoch=_int(data.get("epoch")), variants=str(data.get("variants") or ""),
        state=data.get("state"), requested=None if requested is None else bool(_int(requested)),
        os_platform=data.get("os_platform"), os_major=None if os_major is None else str(os_major),
        archs=data.get("archs"), location=data.get("location"), date=data.get("date"),
        requested_variants=data.get("requested_variants"), negated_variants=data.get("negated_variants"),
        cxx_stdlib=data.get("cxx_stdlib"), cxx_stdlib_overridden=None if overridden is None else _int(overridden))


@dataclass
class FileRow:
    """One row of `files`: a file a port registered; `binary` is None where the schema lacks the column"""

    path: str
    actual_path: str | None
    active: bool
    binary: bool | None

    @property
    def location(self) -> str:
        """Return where the file is on disk: `actual_path`, falling back to `path` when that is NULL

        @returns  the path
        """
        return self.actual_path or self.path


def _file_row(data: Mapping[str, Any]) -> FileRow:
    """Return the row of `files` that a query selected

    @param data  the selected columns, by name
    @returns     the row
    """
    binary = data.get("binary")
    return FileRow(path=str(data["path"]), actual_path=data.get("actual_path"),
                   active=bool(_int(data.get("active"))), binary=None if binary is None else bool(_int(binary)))


@dataclass
class Snapshot:
    """One row of `snapshots`: a `port snapshot` the registry recorded"""

    id: int
    created_at: Any
    note: str | None


# Queries -----------------------------------------------------------------------

PORT_COLUMNS = ("id", "name", "version", "revision", "epoch", "variants", "state", "requested",
                "os_platform", "os_major", "archs", "location", "date")
OPTIONAL_PORT_COLUMNS = ("requested_variants", "negated_variants", "cxx_stdlib", "cxx_stdlib_overridden")
FILE_COLUMNS = ("id", "path", "actual_path", "active", "binary")
_IDENT = re.compile(r"^\w+$")


class Registry:
    """Queries on a backup copy of registry.db, tolerant of older schemas

    `PRAGMA table_info` decides which columns a query selects, so a column an older schema lacks reads
    as None; `sqlite_master` decides whether a table exists.
    """

    def __init__(self, conn: sqlite3.Connection, tmp: tempfile.TemporaryDirectory | None = None) -> None:
        """Query a connection to a copy

        @param conn  the connection, with the `VERSION` collation
        @param tmp   the copy's private directory, removed by `close`; None for a copy the caller keeps
        """
        self.conn = conn
        self._tmp = tmp
        self._columns: dict[str, list[str]] = {}

    @classmethod
    def open_copy(cls, portdbpath: str) -> "Registry":
        """Open a fresh backup of the live registry in a private temporary directory

        @param portdbpath              the instance's `portdbpath`
        @returns                       the registry copy, which `close` removes
        @throws RegistryMissing        registry.db does not exist
        @throws RegistryBusy           another `port` holds the registry, or it keeps changing while it is copied
        @throws sqlite3.DatabaseError  the registry cannot be read as a database
        @throws OSError                the user cannot read the registry
        """
        conn, tmp = open_registry_copy(portdbpath)
        return cls(conn, tmp)

    @classmethod
    def open_backup(cls, path: str) -> "Registry":
        """Open a backup the tool wrote in an earlier step, such as a run's snapshot, read-only

        @param path                    the backup
        @returns                       the registry, which leaves the file in place
        @throws sqlite3.DatabaseError  the file cannot be opened; one that is no database fails at its first query
        """
        conn = sqlite3.connect("file:" + urllib.parse.quote(path) + "?mode=ro", uri=True)
        conn.create_collation("VERSION", vercmp)
        return cls(conn)

    def close(self) -> None:
        """Close the connection and remove the copy's private directory, if it has one"""
        try:
            self.conn.close()
        finally:
            if self._tmp is not None:
                self._tmp.cleanup()
                self._tmp = None

    def __enter__(self) -> "Registry":
        """Return the registry, which leaving the `with` block closes

        @returns  the registry itself
        """
        return self

    def __exit__(self, *exc: Any) -> None:
        """Close the registry

        @param exc  the exception type, value and traceback, which the close ignores
        """
        self.close()

    def columns(self, table: str) -> list[str]:
        """Return the columns of a table, read once per table

        @param table  the table's name, a bare identifier
        @returns      the column names in schema order; empty for a table that does not exist
        """
        if not _IDENT.match(table):
            raise ValueError(f"not a table name: {table!r}")
        if table not in self._columns:
            self._columns[table] = [r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")]
        return self._columns[table]

    def has_table(self, name: str) -> bool:
        """Return whether the schema has a table

        @param name  the table's name
        @returns     True when `sqlite_master` lists it
        """
        row = self.conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone()
        return row is not None

    @property
    def schema_version(self) -> str | None:
        """Return the schema version of the `metadata` table, recorded in scan.json

        @returns  the version, such as 1.215; None without the table or the row
        """
        if not self.has_table("metadata"):
            return None
        row = self.conn.execute("SELECT value FROM metadata WHERE key = 'version'").fetchone()
        return None if row is None else str(row[0])

    def ports(self) -> list[PortRow]:
        """Return every row of every state, `ORDER BY name, version, revision`

        @returns  the rows; empty when `ports` lacks `id` or `name`
        """
        present = set(self.columns("ports"))
        if not {"id", "name"} <= present:
            return []
        wanted = [c for c in PORT_COLUMNS + OPTIONAL_PORT_COLUMNS if c in present]
        order = [c for c in ("name", "version", "revision") if c in present]
        sql = f"SELECT {', '.join(wanted)} FROM ports ORDER BY {', '.join(order)}"
        return [_port_row(dict(zip(wanted, row))) for row in self.conn.execute(sql)]

    def dependencies(self) -> dict[int, list[str]]:
        """Map each port id to the library and runtime dependencies recorded at install

        @returns  the dependency names of each port id, each once, in recorded order
        """
        if not self.has_table("dependencies"):
            return {}
        out: dict[int, list[str]] = {}
        for port_id, name in self.conn.execute("SELECT id, name FROM dependencies ORDER BY rowid"):
            if name and name not in out.setdefault(port_id, []):
                out[port_id].append(name)
        return out

    def _file_columns(self) -> list[str]:
        """Return the columns of `FILE_COLUMNS` that `files` has

        @returns  the column names, in the order of `FILE_COLUMNS`
        """
        present = set(self.columns("files"))
        return [c for c in FILE_COLUMNS if c in present]

    def files(self, port_id: int) -> list[FileRow]:
        """Return the registered files of one port, in registration order

        @param port_id  the port's `id`
        @returns        the files; empty when `files` lacks `path`
        """
        cols = self._file_columns()
        if "path" not in cols:
            return []
        sql = f"SELECT {', '.join(cols)} FROM files WHERE id = ? ORDER BY rowid"
        return [_file_row(dict(zip(cols, row))) for row in self.conn.execute(sql, (port_id,))]

    def files_below(self, directory: str) -> list[tuple[int, FileRow]]:
        """Return the port id and the row of every file whose `path` or `actual_path` lies below `directory`

        The query is a range on the indexed columns, from `<dir>/` up to `<dir>0` excluded, `0` being the
        character after `/`.

        @param directory  an absolute directory
        @returns          `(port id, file)` pairs, in registration order
        """
        cols = self._file_columns()
        if "path" not in cols or "id" not in cols:
            return []
        low, high = directory.rstrip("/") + "/", directory.rstrip("/") + "0"
        where, params = "(path >= ? AND path < ?)", [low, high]
        if "actual_path" in cols:
            where += " OR (actual_path >= ? AND actual_path < ?)"
            params += [low, high]
        sql = f"SELECT {', '.join(cols)} FROM files WHERE {where} ORDER BY rowid"
        out = []
        for row in self.conn.execute(sql, params):
            data = dict(zip(cols, row))
            out.append((int(data["id"]), _file_row(data)))
        return out

    def owner_of(self, path: str) -> str | None:
        """Return the port that registered `path` as `files.path` or `files.actual_path`, an active one first

        @param path  an absolute path
        @returns     the port's name, or None when no port registered it
        """
        cols = self._file_columns()
        if "path" not in cols:
            return None
        cond, params = "f.path = ?", [path]
        if "actual_path" in cols:
            cond += " OR f.actual_path = ?"
            params.append(path)
        order = "f.active DESC" if "active" in cols else "f.rowid"
        sql = f"SELECT p.name FROM files f JOIN ports p ON p.id = f.id WHERE {cond} ORDER BY {order} LIMIT 1"
        row = self.conn.execute(sql, params).fetchone()
        return None if row is None else str(row[0])

    def snapshots(self) -> list[Snapshot]:
        """Return the snapshots the registry records

        @returns  the snapshots by id; empty without the `snapshots` table
        """
        if not self.has_table("snapshots"):
            return []
        return [Snapshot(int(r[0]), r[1], r[2])
                for r in self.conn.execute("SELECT id, created_at, note FROM snapshots ORDER BY id")]

    def snapshot_id(self, note: str) -> int | None:
        """Return the newest snapshot carrying `note` (phase 1, `snapshot-id.txt`)

        @param note  the note given to `port snapshot --create`
        @returns     the snapshot's id; None when no snapshot carries the note
        """
        if not self.has_table("snapshots"):
            return None
        row = self.conn.execute("SELECT id FROM snapshots WHERE note = ? ORDER BY id DESC LIMIT 1", (note,)).fetchone()
        return None if row is None else int(row[0])


# Integrity -----------------------------------------------------------------------

STATUS_LABELS = {"missing": "RegistryMissing", "busy": "RegistryBusy", "damaged": "RegistryDamaged",
                 "unreadable": "RegistryUnreadable"}


@dataclass
class RegistryCheck:
    """The outcome of the registry check: `ok`, `missing`, `busy`, `damaged` or `unreadable`"""

    status: str
    detail: str | None = None

    @property
    def message(self) -> str | None:
        """Return `<label>: <detail>` for a failed check, the form `Instance.inventory_error` carries

        @returns  the message; None for a check that passed
        """
        if self.status == "ok":
            return None
        return f"{STATUS_LABELS[self.status]}: {self.detail or self.status}"


def _integrity(path: str) -> list[str]:
    """Run `PRAGMA integrity_check` on a copy

    @param path                    the copy
    @returns                       the lines of the check, `["ok"]` for a sound database
    @throws sqlite3.DatabaseError  the file is no database
    """
    conn = sqlite3.connect(path)
    try:
        conn.create_collation("VERSION", vercmp)
        return [str(r[0]) for r in conn.execute("PRAGMA integrity_check")]
    finally:
        conn.close()


def check_registry(portdbpath: str, attempts: int = 3, wait_s: float = 30.0) -> RegistryCheck:
    """Back the registry up and run `PRAGMA integrity_check` on the copy

    A failed check or `sqlite3.DatabaseError` is retried, then gives `damaged`; `missing` means
    NO_REGISTRY, `busy` another `port` at work, and `unreadable` (a file the user cannot read) CANNOT_RUN.

    @param portdbpath  the instance's `portdbpath`
    @param attempts    the backups tried before the registry counts as damaged
    @param wait_s      the seconds without progress after which a backup is busy
    @returns           the outcome
    """
    detail: str | None = None
    for _ in range(attempts):
        with tempfile.TemporaryDirectory(prefix="brew-ports-registry-check-") as tmp:
            dest = os.path.join(tmp, "registry.db")
            try:
                backup_registry(portdbpath, dest, wait_s)
                result = _integrity(dest)
            except RegistryMissing as exc:
                return RegistryCheck("missing", str(exc))
            except RegistryBusy as exc:
                return RegistryCheck("busy", str(exc))
            except sqlite3.DatabaseError as exc:
                detail = str(exc)
                continue
            except OSError as exc:
                return RegistryCheck("unreadable", f"{type(exc).__name__}: {exc}")
        if result == ["ok"]:
            return RegistryCheck("ok")
        detail = "; ".join(result[:3])
    return RegistryCheck("damaged", detail)


def registry_path(portdbpath: str) -> str:
    """Return the path of an instance's registry.db

    @param portdbpath  the instance's `portdbpath`
    @returns           `<portdbpath>/registry/registry.db`
    """
    return os.path.join(portdbpath, REGISTRY_REL)


def image_archives(portdbpath: str) -> dict[str, list[str]]:
    """List the image archives and directories under `<portdbpath>/software/<name>/`

    @param portdbpath        the instance's `portdbpath`
    @returns                 the entries of each port name that has any; empty without `software`
    @throws PermissionError  a directory the user cannot read, so an unreadable tree never reads as empty
    """
    root = os.path.join(portdbpath, "software")
    try:
        names = sorted(os.listdir(root))
    except FileNotFoundError:
        return {}
    out: dict[str, list[str]] = {}
    for name in names:
        if name.startswith("."):
            continue
        try:
            entries = sorted(e for e in os.listdir(os.path.join(root, name)) if not e.startswith("."))
        except NotADirectoryError:
            continue
        if entries:
            out[name] = entries
    return out

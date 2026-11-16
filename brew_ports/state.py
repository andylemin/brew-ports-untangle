"""State directory, run directories, lock, journal, backups and dirty marker"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import secrets
import shutil
import time
from collections.abc import Iterator
from typing import Any

DEFAULT_STATE_DIR = os.path.join("~", "Library", "Application Support", "brew-ports")


class LockHeld(Exception):
    """Another brew-ports process holds the state lock (exit 3)"""


def slug(path: str) -> str:
    """Turn an absolute path into one file name: slashes become `%`

    @param path  an absolute path
    @returns     the file name, which starts with `%`
    """
    return path.replace("/", "%")


def unslug(text: str) -> str:
    """Turn a `slug` back into its path; a text that is not one comes back unchanged

    @param text  a file name that `slug` made, or any other text
    @returns     the path, or the text when it does not start with `%`
    """
    return text.replace("%", "/") if text.startswith("%") else text


def now_iso() -> str:
    """Return the local time in ISO 8601 with its UTC offset, as the state files record it

    @returns  the time, such as `2026-11-12T00:00:00+0000`
    """
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _write_atomic(path: str, data: str) -> None:
    """Write a file through a synced temporary file, so a crash leaves either the old content or the new

    @param path  the file
    @param data  the new content
    """
    tmp = f"{path}.tmp-{secrets.token_hex(4)}"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class Journal:
    """`journal.jsonl`: one JSON object per line, flushed and synced per line"""

    def __init__(self, path: str) -> None:
        """Open the journal of a run; the first append creates the file

        @param path  the `journal.jsonl` file
        """
        self.path = path

    def append(self, record: dict[str, Any]) -> None:
        """Append one record as a JSON line, synced before the call returns

        @param record  a JSON-ready record
        """
        line = json.dumps(record, sort_keys=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def entries(self) -> list[dict[str, Any]]:
        """Return the journal's entries, without a line a crash cut short

        @returns  the records in file order; empty when the journal does not exist
        """
        try:
            with open(self.path, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except FileNotFoundError:
            return []
        out = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue  # a line cut short by a crash
        return out

    def result(self, phase: Any, action_id: str) -> str | None:
        """Return the last result an action recorded in a phase

        @param phase      the phase as the journal records it: a number, or `rollback`
        @param action_id  the action's id
        @returns          `ok` or `failed`, or None when the action recorded no result
        """
        found = None
        for entry in self.entries():
            if "result" in entry and entry.get("action_id") == action_id and entry.get("phase") == phase:
                found = entry["result"]
        return found


class RunDir:
    """One run directory under `<state>/runs/`"""

    def __init__(self, path: str) -> None:
        """Open an existing run directory

        @param path  the run directory; its name is the run id
        """
        self.path = path
        self.run_id = os.path.basename(path)
        self.journal = Journal(os.path.join(path, "journal.jsonl"))

    def sub(self, *parts: str) -> str:
        """Return a path inside the run directory

        @param parts  the path's components below the run directory
        @returns      the joined path
        """
        return os.path.join(self.path, *parts)

    def ensure(self, *parts: str) -> str:
        """Return a directory inside the run directory, creating it when absent

        @param parts  the directory's components below the run directory
        @returns      the directory's path
        """
        path = self.sub(*parts)
        os.makedirs(path, exist_ok=True)
        return path

    @property
    def out_dir(self) -> str:
        """Return the run's `out` directory, created on first use

        @returns  the directory's path
        """
        return self.ensure("out")

    @property
    def commands_log(self) -> str:
        """Return the path of the run's `commands.log`

        @returns  the path; the file may not exist yet
        """
        return self.sub("commands.log")

    def backup_path(self, abs_path: str) -> str:
        """Return where `backup_first_copy` keeps its copy of a file

        @param abs_path  the file's absolute path
        @returns         `backup/<slug>` inside the run directory
        """
        return self.sub("backup", slug(abs_path))

    def backup_first_copy(self, abs_path: str) -> str | None:
        """Copy a file into `backup/` once per run

        The first copy wins, so a resumed run never overwrites the copy of the original.

        @param abs_path  the file's absolute path
        @returns         the copy, or None when the file does not exist
        """
        dest = self.backup_path(abs_path)
        if os.path.lexists(dest):
            return dest
        if not os.path.lexists(abs_path):
            return None
        self.ensure("backup")
        shutil.copy2(abs_path, dest, follow_symlinks=True)
        return dest

    def etc_copy(self, path: str, rel: str) -> str | None:
        """Keep a readable first copy of a root-owned `/etc` file at `<run>/backup/etc/<rel>`

        The report and `rollback` read this copy; root restores the file from the root backup store.

        @param path  the file
        @param rel   the file's path below `/etc`, such as `paths.d/homebrew`
        @returns     the copy, or None when the file is absent
        """
        dest = self.sub("backup", "etc", rel)
        if os.path.lexists(dest):
            return dest
        if not os.path.lexists(path):
            return None
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(path, dest)
        return dest

    def write_json(self, name: str, text: str) -> str:
        """Write a file of the run directory atomically

        @param name  the file's name, such as `scan.json`
        @param text  the file's content
        @returns     the file's path
        """
        path = self.sub(name)
        _write_atomic(path, text)
        return path


class StateDir:
    """The state directory: the run directories, the lock, the `latest` link and the dirty marker"""

    def __init__(self, path: str | None = None) -> None:
        """Name a state directory; nothing is created until a command needs it

        @param path  the directory, `~` expanded; None takes `~/Library/Application Support/brew-ports`
        """
        self.path = os.path.abspath(os.path.expanduser(path or DEFAULT_STATE_DIR))
        self._lock_fd: int | None = None

    @property
    def runs(self) -> str:
        """Return the directory that holds the run directories

        @returns  `<state>/runs`
        """
        return os.path.join(self.path, "runs")

    def ensure(self) -> None:
        """Create the `runs` directory with mode 0700, and the state directory above it"""
        os.makedirs(self.runs, mode=0o700, exist_ok=True)

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        """Hold the exclusive state lock for the whole command

        @returns          a context manager that holds the lock until its block ends
        @throws LockHeld  when another brew-ports process holds the lock
        """
        self.ensure()
        fd = os.open(os.path.join(self.path, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                    raise LockHeld("another brew-ports is running") from None
                raise
            self._lock_fd = fd
            yield
        finally:
            self._lock_fd = None
            os.close(fd)

    def new_run(self) -> RunDir:
        """Create a fresh run directory and point `latest` at it

        `os.mkdir` fails when the name exists, so an existing run directory is never reused.

        @returns  the run directory
        """
        self.ensure()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        while True:
            name = f"{stamp}-{secrets.token_hex(3)}"
            path = os.path.join(self.runs, name)
            try:
                os.mkdir(path, 0o700)
                break
            except FileExistsError:
                continue
        self._point_latest(name)
        return RunDir(path)

    def _point_latest(self, name: str) -> None:
        """Point the `latest` link at a run, replacing the link atomically

        @param name  the run id
        """
        link = os.path.join(self.path, "latest")
        tmp = f"{link}.tmp-{secrets.token_hex(4)}"
        os.symlink(os.path.join("runs", name), tmp)
        os.replace(tmp, link)

    def run(self, run_id: str) -> RunDir:
        """Return an existing run directory by its id

        @param run_id              the run directory's name
        @returns                   the run directory
        @throws ValueError         when the id is empty, `.`, `..` or holds a slash
        @throws FileNotFoundError  when no run has that id
        """
        if not run_id or "/" in run_id or run_id in (".", ".."):
            raise ValueError(f"invalid run id: {run_id!r}")
        path = os.path.join(self.runs, run_id)
        if not os.path.isdir(path):
            raise FileNotFoundError(path)
        return RunDir(path)

    def run_ids(self) -> list[str]:
        """Return the ids of the run directories, oldest first: an id starts with its creation time

        @returns  the ids; empty when there are none
        """
        try:
            names = os.listdir(self.runs)
        except FileNotFoundError:
            return []
        return sorted(n for n in names if os.path.isdir(os.path.join(self.runs, n)))

    def latest_run(self) -> RunDir | None:
        """Return the newest run directory by its id

        @returns  the run directory, or None when there is none
        """
        ids = self.run_ids()
        return RunDir(os.path.join(self.runs, ids[-1])) if ids else None

    # Dirty marker -------------------------------------------------------

    @property
    def dirty_path(self) -> str:
        """Return the path of the dirty marker

        @returns  `<state>/dirty`
        """
        return os.path.join(self.path, "dirty")

    def touch_dirty(self, run_id: str, command: str) -> None:
        """Record the run that is about to change the host

        @param run_id   the run's id
        @param command  the command that changes the host, such as `apply`
        """
        self.ensure()
        _write_atomic(self.dirty_path, json.dumps({"run_id": run_id, "command": command, "ts": now_iso()}))

    def dirty(self) -> dict[str, Any] | None:
        """Return the dirty marker

        @returns  the run id, command and time it records, with its `mtime_ns`; None when it is absent or
                  cannot be read
        """
        try:
            with open(self.dirty_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, ValueError):
            return None
        data["mtime_ns"] = os.stat(self.dirty_path).st_mtime_ns
        return data

    def older_than_dirty(self, path: str) -> bool:
        """Return whether a file was written before the last command that changed the host

        @param path  the file
        @returns     True when the dirty marker is newer than the file; False without a marker
        """
        marker = self.dirty()
        if marker is None:
            return False
        return os.stat(path).st_mtime_ns < marker["mtime_ns"]

    def marker_blocks_resume(self, run_id: str, started_ns: int) -> bool:
        """Return whether another command touched the marker after the run started, which refuses a resume

        @param run_id      the resumed run's id; its own touches do not count
        @param started_ns  the run's start, in nanoseconds since the epoch
        @returns           True when the resume must be refused
        """
        marker = self.dirty()
        if marker is None:
            return False
        return marker.get("run_id") != run_id and marker["mtime_ns"] > started_ns


def write_user_file(path: str, content: str) -> None:
    """Run the user form of the `write` action: create a file with mode 0644, or rewrite it in place

    Rewriting in place keeps the file's inode, mode, ACLs, extended attributes and hard links.

    @param path     the file; a symlink is refused
    @param content  the file's new text
    """
    data = content.encode("utf-8")
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    except FileNotFoundError:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)

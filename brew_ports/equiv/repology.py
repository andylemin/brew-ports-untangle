"""Repology lookups for the resolver under `--repology`, and the curl JSON fetch the PyPI lookups share

Every request goes through `/usr/bin/curl` as an action the runner runs, so a run's journal records it and
`FakeRunner` answers it in the tests.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import tempfile
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeGuard

from .. import __version__
from ..model import Action, Manager, OnFailure, Package
from ..runner import curl_argv
from ..state import slug

PROJECT_BY = "https://repology.org/tools/project-by"
USER_AGENT = f"brew-ports/{__version__} (+https://github.com/andylemin/brew-ports-untangle)"
CACHE_FILE = "repology-cache.json"
CACHE_VERSION = 1
TTL_S = 30 * 86400
INTERVAL_S = 1.0
MAX_FAILURES = 3
ELIGIBLE = frozenset(("newest", "devel", "unique", "rolling", "outdated"))
KEPT_FIELDS = ("repo", "srcname", "binname", "version", "status")
# The source package's repository and name type: a formula and a cask token are srcnames,
# a port is a binname (its srcname is `category/port`).
SOURCE_QUERY = {"formula": ("homebrew", "srcname"), "cask": ("homebrew_casks", "srcname"),
                "port": ("macports", "binname")}
TARGET_REPOS = {Manager.BREW: (("homebrew", "formula"), ("homebrew_casks", "cask")),
                Manager.PORTS: (("macports", "port"),)}
_NOT_FOUND = re.compile(r"returned error: 404\b")


@dataclass
class Fetched:
    """The outcome of one curl JSON fetch

    `data` is the parsed document of an ok fetch; `error` says why a fetch is missing or failed.
    """

    status: str                 # "ok", "missing" (HTTP 404) or "failed"
    data: Any = None
    error: str = ""


def _phase(runner: Any) -> int:
    """Return the runner's current phase, 0 outside a phase

    @param runner  the runner, whose phase starts the action ids
    @returns       the phase number
    """
    return 0 if runner.phase is None else runner.phase


def fetch_json(runner: Any, url: str, output: str, action_id: str, description: str, *,
               user_agent: str = USER_AGENT) -> Fetched:
    """Fetch a JSON document through curl into `output`, removing a stale `output` first

    An HTTP error exits 22, or 56 from the macOS curl, so a 404 is read from the "returned error: 404" text.

    @param runner       the runner that runs curl
    @param url          the document's URL
    @param output       the file curl writes
    @param action_id    the id of the curl action, which starts with the phase
    @param description  the text shown for the download
    @param user_agent   the `User-Agent` of the request
    @returns            ok with the document, missing for an HTTP 404, else failed with the error
    """
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(output)
    action = Action(action_id=action_id, kind="command", argv=curl_argv(url, output, user_agent=user_agent),
                    sudo=False, description=description, on_failure=OnFailure.PROBE, read_only=True)
    result = runner.run(action)
    if result.exit != 0:
        stderr = result.stderr().strip()
        if _NOT_FOUND.search(stderr):
            return Fetched("missing", error=stderr)
        lines = stderr.splitlines()
        return Fetched("failed", error=lines[-1] if lines else f"curl exit {result.exit}")
    try:
        with open(output, encoding="utf-8") as fh:
            return Fetched("ok", json.load(fh))
    except (OSError, ValueError) as exc:
        return Fetched("failed", error=f"unreadable answer from {url}: {exc}")


def query_url(repo: str, name_type: str, name: str) -> str:
    """Return the `project-by` URL of a package, which redirects to its project's `api_v1_project` JSON

    @param repo       the Repology repository, such as `homebrew` or `macports`
    @param name_type  `srcname` or `binname`, the kind of name `name` is
    @param name       the package's name in that repository
    @returns          the URL, its query encoded
    """
    query = urllib.parse.urlencode([("repo", repo), ("name_type", name_type), ("name", name),
                                    ("target_page", "api_v1_project")])
    return PROJECT_BY + "?" + query


@dataclass
class Entry:
    """An eligible package of a target repository in the source package's Repology project"""

    kind: str                   # formula, cask, port
    name: str
    version: str | None
    status: str


class Repology:
    """Repology `project-by` lookups, cached for 30 days in the state directory

    Requests stay one second apart and name the tool in their `User-Agent`, as Repology asks of API clients.
    """

    def __init__(self, runner: Any, state_dir: str, downloads: str | None = None, *,
                 clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        """Start a client that has made no request yet

        @param runner     the runner that runs curl
        @param state_dir  the state directory, which holds the cache
        @param downloads  the directory for the answers; None for a temporary one
        @param clock      returns the wall-clock time, for the age of a cache entry
        @param monotonic  returns the monotonic time, for the pace of the requests
        @param sleep      waits for a number of seconds
        """
        self.runner = runner
        self.cache_path = os.path.join(state_dir, CACHE_FILE)
        self.downloads = downloads or tempfile.mkdtemp(prefix="brew-ports-repology-")
        self.clock = clock
        self.monotonic = monotonic
        self.sleep = sleep
        self.error = ""
        self.failures = 0           # failed requests in a row; MAX_FAILURES stop further lookups
        self.requests = 0
        self._entries: dict[str, Any] | None = None
        self._last: float | None = None

    @property
    def stopped(self) -> bool:
        """Return whether `MAX_FAILURES` failed requests in a row stop further lookups

        @returns  True once that many requests failed in a row
        """
        return self.failures >= MAX_FAILURES

    # Cache --------------------------------------------------------------------------

    def entries(self) -> dict[str, Any]:
        """Return the cache entries by `<repo>/<name_type>/<name>`; an unreadable or foreign file counts as empty

        @returns  the entries, read from the cache file on first use
        """
        if self._entries is None:
            try:
                with open(self.cache_path, encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                data = None
            entries = data.get("entries") if isinstance(data, dict) and data.get("version") == CACHE_VERSION else None
            self._entries = entries if isinstance(entries, dict) else {}
        return self._entries

    def fresh(self, record: Any) -> TypeGuard[dict[str, Any]]:
        """Return whether a cache record is younger than 30 days

        @param record  a cache entry, or None for a key without one
        @returns       True for a record with a package list, fetched less than `TTL_S` ago
        """
        if not isinstance(record, dict) or not isinstance(record.get("packages"), list):
            return False
        fetched = record.get("fetched")
        return isinstance(fetched, (int, float)) and 0 <= self.clock() - fetched < TTL_S

    def save(self) -> None:
        """Write the fresh entries in place of the cache file, atomically"""
        entries = {key: record for key, record in self.entries().items() if self.fresh(record)}
        os.makedirs(os.path.dirname(self.cache_path) or ".", exist_ok=True)
        tmp = f"{self.cache_path}.tmp-{secrets.token_hex(4)}"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"version": CACHE_VERSION, "entries": entries}, fh, indent=1, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.cache_path)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)

    # Requests -----------------------------------------------------------------------

    def pace(self) -> None:
        """Sleep so that requests start at least one second apart"""
        if self._last is not None:
            wait = INTERVAL_S - (self.monotonic() - self._last)
            if wait > 0:
                self.sleep(wait)
        self._last = self.monotonic()

    def project(self, repo: str, name_type: str, name: str) -> list[dict[str, Any]] | None:
        """Return the packages of the project `name` belongs to in `repo`, or None when the lookup failed

        A 404 gives [] and is cached like an answer; a failure is not cached.

        @param repo       the Repology repository of the name, such as `macports`
        @param name_type  `srcname` or `binname`, the kind of name `name` is
        @param name       the package's name in `repo`
        @returns          the packages, each with the `KEPT_FIELDS` it has; None when the lookup failed or stopped
        """
        key = f"{repo}/{name_type}/{name}"
        record = self.entries().get(key)
        if self.fresh(record):
            return list(record["packages"])
        if self.stopped:
            return None
        self.pace()
        self.requests += 1
        fetched = fetch_json(self.runner, query_url(repo, name_type, name),
                             os.path.join(self.downloads, "repology", slug(key) + ".json"),
                             f"{_phase(self.runner)}.repology.{repo}.{name}",
                             f"look up {repo} {name} on Repology")
        if fetched.status == "failed" or (fetched.status == "ok" and not isinstance(fetched.data, list)):
            self.failures += 1
            self.error = f"lookup of {name} failed: {fetched.error or 'the answer is not a package list'}"
            if self.stopped:
                self.error += "; no further Repology lookups"
            return None
        self.failures = 0
        packages = [{k: p[k] for k in KEPT_FIELDS if p.get(k) is not None}
                    for p in (fetched.data or []) if isinstance(p, dict)]
        self.entries()[key] = {"fetched": self.clock(), "packages": packages}
        self.save()
        return packages

    def candidates(self, pkg: Package, target: Manager) -> list[Entry] | None:
        """Return the eligible packages of the target's repositories in the source package's project

        Only the `ELIGIBLE` statuses count, so a `legacy` entry never does.

        @param pkg     the source package; a kind other than formula, cask and port has no candidates
        @param target  the target manager
        @returns       the entries, one per kind and name; None when the lookup failed
        """
        query = SOURCE_QUERY.get(pkg.kind)
        if query is None:
            return []
        packages = self.project(query[0], query[1], pkg.name)
        if packages is None:
            return None
        out: list[Entry] = []
        for repo, kind in TARGET_REPOS[target]:
            for package in packages:
                if package.get("repo") != repo or package.get("status") not in ELIGIBLE:
                    continue
                name = package.get("binname") if repo == "macports" else package.get("srcname")
                if not name and repo == "macports" and package.get("srcname"):
                    name = str(package["srcname"]).rsplit("/", 1)[-1]
                if name and all(e.kind != kind or e.name != name for e in out):
                    out.append(Entry(kind, str(name), package.get("version"), str(package["status"])))
        return out

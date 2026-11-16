"""Builders for the equivalence tests: a fixture catalogue and PortIndex, source packages, and fake HTTP

The PortIndex is read with the test list splitter, so no tkinter is needed.
"""

from __future__ import annotations

import datetime
import io
import itertools
import json
import os
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from brew_ports import report, runner as runner_mod
from brew_ports.equiv import resolver
from brew_ports.homebrew import catalogue as cat
from brew_ports.macports.portindex import PortIndex
from brew_ports.model import Manager, Package
from tests.unit.fixtures.macports.builders import tcl_splitlist, write_portindex
from tests.unit.helpers import make_package

HERE = os.path.dirname(os.path.abspath(__file__))
TODAY = datetime.date(2026, 11, 13)
BREW_SOURCE = "/usr/local"
BREW_TARGET = "/opt/homebrew"
PORTS_PREFIX = "/opt/local"
PORTS_SOURCE = "rsync://rsync.macports.org/macports/release/tarballs/ports.tar"
NOT_FOUND = runner_mod.FakeResponse(exit=56, stderr="curl: (56) The requested URL returned error: 404\n")
_COUNTER = itertools.count()


def load(name: str) -> Any:
    """Return the parsed JSON of a fixture file beside this module

    @param name  the file's name
    @returns     the document
    """
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return json.load(fh)


# Homebrew -------------------------------------------------------------------------

def catalogue(home: str, today: datetime.date = TODAY) -> cat.Catalogue:
    """Return the fixture catalogue, its casks installing into a writable app directory under `home`

    So only a `pkg` artifact makes a cask privileged.

    @param home   the user's home, which gets the `Applications` directory
    @param today  the date the lifecycle checks compare with
    @returns      the catalogue of a Homebrew target at `BREW_TARGET`
    """
    apps = os.path.join(home, "Applications")
    os.makedirs(apps, exist_ok=True)
    dirs = cat.cask_dirs(BREW_TARGET, {"HOME": home})
    dirs["appdir"] = apps
    return cat.Catalogue.from_payload(load("catalogue.json"), prefix=BREW_TARGET, dirs=dirs, home=home, today=today)


def formula(name: str, prefix: str = BREW_SOURCE, **kw: Any) -> Package:
    """Return a source formula with the fixture entry's version, homepage, executables and dependencies

    @param name    a formula of the fixture catalogue
    @param prefix  the source instance's prefix
    @param kw      the package fields that replace the fixture's
    @returns       the package
    """
    entry = load("catalogue.json")["formulae"][name]
    version = entry["stable_version"] + (f"_{entry['revision']}" if entry.get("revision") else "")
    fields: dict[str, Any] = {"version": version, "homepage": entry.get("homepage"),
                              "executables": list(entry.get("executables", [])),
                              "deps": [d for d in entry.get("stable_dependencies", []) if isinstance(d, str)]}
    fields.update(kw)
    return make_package(name, "formula", prefix, **fields)


def cask(token: str, version: str = "1.0", prefix: str = BREW_SOURCE, **kw: Any) -> Package:
    """Return a source cask

    @param token    the cask's token
    @param version  its version
    @param prefix   the source instance's prefix
    @param kw       more package fields, such as `homepage` or `caskroom_data`
    @returns        the package
    """
    return make_package(token, "cask", prefix, version=version, **kw)


# MacPorts --------------------------------------------------------------------------

def _tcl(value: str) -> str:
    """Return `value` as a Tcl list element, braced when it holds a space or a character Tcl treats specially

    @param value  the text
    @returns      the element
    """
    return "{%s}" % value if not value or any(c in value for c in " \t\n{}\\\"[]$;") else value


def tcl_entry(fields: Mapping[str, Any]) -> str:
    """Return one PortIndex entry line: each key, then its value as a Tcl list element

    @param fields  the entry's keys and values, in order
    @returns       the line
    """
    return " ".join(f"{key} {_tcl(str(value))}" for key, value in fields.items())


def port_entries(drop: Iterable[str] = (), add: Iterable[Mapping[str, Any]] = ()) -> list[tuple[str, str]]:
    """Return the fixture PortIndex entries as `(name, line)` pairs, their revision and epoch 0 unless given

    @param drop  the names of the fixture ports to leave out
    @param add   more entries, as key-value mappings
    @returns     the pairs, the fixture's first
    """
    dropped = set(drop)
    out = []
    for fields in [e for e in load("portindex.json") if e["name"] not in dropped] + list(add):
        fields = dict(fields)
        fields.setdefault("revision", 0)
        fields.setdefault("epoch", 0)
        out.append((fields["name"], tcl_entry(fields)))
    return out


def portindex(directory: str, drop: Iterable[str] = (), add: Iterable[Mapping[str, Any]] = ()) -> PortIndex:
    """Return the fixture PortIndex, written as `portindex` writes it in a fresh directory below `directory`

    @param directory  where the fresh directory goes
    @param drop       the names of the fixture ports to leave out
    @param add        more entries, as key-value mappings
    @returns          the PortIndex, read with the test list splitter
    """
    path = write_portindex(os.path.join(directory, f"ports-{next(_COUNTER)}"), port_entries(drop, add))
    return PortIndex(path, splitlist=tcl_splitlist, source=PORTS_SOURCE)


def port(name: str, version: str = "1.0", prefix: str = PORTS_PREFIX, revision: int = 0, **kw: Any) -> Package:
    """Return a source port at `<version>_<revision>`, installed from the rsync ports tree

    @param name      the port's name
    @param version   its version, without the revision
    @param prefix    the source instance's prefix
    @param revision  its revision
    @param kw        the package fields that replace the defaults
    @returns         the package
    """
    full = f"{version}_{revision}"
    fields: dict[str, Any] = {"version": full, "spec_args": [name, "@" + full], "linked": None,
                              "origin": PORTS_SOURCE}
    fields.update(kw)
    return make_package(name, "port", prefix, **fields)


# Contexts -----------------------------------------------------------------------------

def brew_context(home: str, **kw: Any) -> resolver.Context:
    """Return a context for a Homebrew target at /opt/homebrew with the fixture catalogue

    @param home  the user's home, for the catalogue's app directory
    @param kw    more context fields
    @returns     the context
    """
    return resolver.Context(target=Manager.BREW, catalogue=catalogue(home), **kw)


def ports_context(home: str, drop: Iterable[str] = (), add: Iterable[Mapping[str, Any]] = (),
                  **kw: Any) -> resolver.Context:
    """Return a context for a MacPorts target; the Homebrew source at /usr/local has the fixture catalogue

    @param home  the user's home, for the catalogue's app directory and the PortIndex directory
    @param drop  the names of the fixture ports to leave out
    @param add   more PortIndex entries
    @param kw    more context fields; `source_catalogues` replaces the fixture's
    @returns     the context
    """
    fields: dict[str, Any] = {"source_catalogues": {BREW_SOURCE: catalogue(home)}}
    fields.update(kw)
    return resolver.Context(target=Manager.PORTS, portindex=portindex(home, drop, add), **fields)


# HTTP --------------------------------------------------------------------------------

class QuietConsole(report.Console):
    """A console that writes into memory, so a test prints nothing"""

    def __init__(self) -> None:
        """Write both streams into memory"""
        super().__init__(stream=io.StringIO(), err=io.StringIO())


Page = dict[str, Any] | list[Any] | runner_mod.FakeResponse
Argv = tuple[str, ...]


def http(pages: Mapping[str, Page], seen: list[Argv] | None = None) -> Callable[[Argv], runner_mod.FakeResponse]:
    """Return a fake HTTP server for curl argv, where an unknown URL is a 404

    A JSON page is written to the `--output` path, as curl writes it; a FakeResponse is returned as it is.

    @param pages  the answer by URL: a JSON document or a response
    @param seen   receives every argv the server answers; None to keep none
    @returns      the responder
    """
    def respond(key: Argv) -> runner_mod.FakeResponse:
        if seen is not None:
            seen.append(key)
        url = key[-1]
        page = pages.get(url)
        if page is None:
            return NOT_FOUND
        if isinstance(page, runner_mod.FakeResponse):
            return page
        with open(key[key.index("--output") + 1], "w", encoding="utf-8") as fh:
            json.dump(page, fh)
        return runner_mod.FakeResponse()
    return respond


def web_runner(tmp: str, pages: Mapping[str, Page], seen: list[Argv] | None = None) -> runner_mod.FakeRunner:
    """Return a FakeRunner that answers every command with `http(pages)`

    @param tmp    the test's directory, which receives the runner's output
    @param pages  the answer by URL
    @param seen   receives every argv; None to keep none
    @returns      the runner
    """
    return runner_mod.FakeRunner(default=http(pages, seen), console=QuietConsole(), environ={"HOME": "/Users/alice"},
                                 out_dir=os.path.join(tmp, "out"))


def pypi_page(name: str, urls: Mapping[str, str], version: str = "1.0", home_page: str = "") -> dict[str, Any]:
    """Return a trimmed PyPI JSON answer

    @param name       the project's name
    @param urls       its `project_urls`, by label
    @param version    its version
    @param home_page  its `home_page`; empty for none
    @returns          the document
    """
    return {"info": {"name": name, "version": version, "home_page": home_page, "project_urls": dict(urls),
                     "project_url": f"https://pypi.org/project/{name}/",
                     "package_url": f"https://pypi.org/project/{name}/"}, "releases": {}}


def pypi_url(name: str) -> str:
    """Return the URL of a project's PyPI JSON, the one the resolver fetches

    @param name  the project's name
    @returns     the URL
    """
    return resolver.PYPI_URL % name

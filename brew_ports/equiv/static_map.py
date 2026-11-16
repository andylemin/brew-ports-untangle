"""The curated pairs of `data/equivalents.json`: the names `canon()` cannot fold onto each other

The file is a JSON list of `{"brew": ..., "ports": ..., "note": ...}` objects. A formula whose software MacPorts
splits into several ports lists the others under `"companions"`.
"""

from __future__ import annotations

import functools
import importlib.resources
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

DATA_PACKAGE = "brew_ports.data"
DATA_FILE = "equivalents.json"
_AT_VERSION = re.compile(r"@[^@]*$")


@dataclass(frozen=True)
class Pair:
    """One curated pair: a Homebrew name and the MacPorts name of the same software"""

    brew: str
    ports: str
    note: str = ""
    companions: tuple[str, ...] = ()     # the ports installed beside `ports`, which the formula holds too


def parse(text: str) -> list[Pair]:
    """Return the pairs of an equivalents file, skipping an entry without both names

    @param text  the JSON text of an equivalents file
    @returns     the pairs in file order, each with the companions that are names; empty when the text holds no list
    """
    data = json.loads(text)
    out: list[Pair] = []
    for item in data if isinstance(data, list) else []:
        if isinstance(item, dict) and isinstance(item.get("brew"), str) and isinstance(item.get("ports"), str):
            listed = item.get("companions")
            companions = tuple(c for c in listed if isinstance(c, str)) if isinstance(listed, list) else ()
            out.append(Pair(item["brew"], item["ports"], str(item.get("note") or ""), companions))
    return out


def shipped_text() -> str:
    """Return the text of the `equivalents.json` the package ships in `brew_ports/data`

    @returns  the file's JSON text
    """
    return importlib.resources.files(DATA_PACKAGE).joinpath(DATA_FILE).read_text(encoding="utf-8")


class StaticMap:
    """The curated pairs, looked up by the name of either side"""

    def __init__(self, pairs: Sequence[Pair]) -> None:
        """Keep the pairs in their file order

        @param pairs  the curated pairs
        """
        self.pairs = list(pairs)

    def ports_for(self, formula: str) -> list[Pair]:
        """Return the pairs whose Homebrew name is the formula's, exactly or without its `@<version>`

        So `icu4c@78` meets the pair of `icu4c`; the version gate then checks the major.

        @param formula  a formula name, in any case
        @returns        the matching pairs, in file order
        """
        name = formula.lower()
        names = {name, _AT_VERSION.sub("", name)}
        return [p for p in self.pairs if p.brew.lower() in names]

    def brew_for(self, port: str) -> list[Pair]:
        """Return the pairs that name the port as their MacPorts name or a companion, ignoring case as MacPorts does

        @param port  a port name
        @returns     the matching pairs, in file order
        """
        key = port.lower()
        return [p for p in self.pairs if key in {name.lower() for name in (p.ports, *p.companions)}]


@functools.lru_cache(maxsize=None)
def shipped() -> StaticMap:
    """Return the static map shipped in `brew_ports/data`, read once

    @returns  the map, the same object on every call
    """
    return StaticMap(parse(shipped_text()))

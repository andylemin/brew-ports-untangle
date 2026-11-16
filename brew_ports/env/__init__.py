"""Environment, linkage, interpreter and launchd analysis, and the `scan` text that reports it

`PrefixIndex` answers the question every module here asks: which instance a path belongs to.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from typing import Any

from .. import system
from ..model import Instance, Service
from ..report import table


def roots_of(instance: Instance) -> tuple[str, ...]:
    """Return the directories that belong to an instance: its `owned_roots`, else its prefix

    @param instance  a Homebrew or MacPorts instance
    @returns         the owned roots; the prefix alone when the instance records none
    """
    return tuple(instance.owned_roots) or (instance.prefix,)


def root_spellings(instance: Instance, root: str) -> list[str]:
    """Return every text spelling of one owned root, built from the prefix spellings

    A `/usr/local` instance owns `Cellar`, `opt` and so on below it, so each
    recorded spelling of the prefix gets the root's suffix appended.

    @param instance  the instance that owns the root
    @param root      one of its owned roots
    @returns         the root itself first, then the other spellings, without duplicates or empty texts
    """
    prefix = instance.prefix.rstrip("/") or "/"
    out = [root]
    if root == prefix or root.startswith(prefix + "/"):
        suffix = root[len(prefix):]
        for spelling in instance.spellings or (instance.prefix,):
            out.append(spelling.rstrip("/") + suffix)
    seen: list[str] = []
    for item in out:
        if item and item not in seen:
            seen.append(item)
    return seen


def _nearest_existing(path: str) -> str | None:
    """Return the path itself, or its nearest ancestor, that exists

    @param path  a prefix, which may be gone
    @returns     the first of the path and its ancestors that exists; None when none does
    """
    current = path
    while True:
        if os.path.exists(current):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def fold_case_for(instance: Instance) -> bool:
    """Return whether text naming this instance compares case-insensitively

    A prefix that is gone is judged by its nearest existing ancestor.

    @param instance  the instance whose prefix is judged
    @returns         True when that path lies on a case-insensitive volume
    """
    existing = _nearest_existing(instance.prefix)
    return existing is not None and system.case_insensitive(existing)


class PrefixIndex:
    """Which instance a path lies under: by the file identity of an owned root above its realpath, else by text"""

    def __init__(self, instances: Sequence[Instance]) -> None:
        """Index the owned roots of every instance by file identity and by each text spelling

        @param instances  the instances; of two that share a root, the first listed owns it by identity
        """
        self.instances = list(instances)
        self._by_ident: dict[tuple[int, int], Instance] = {}
        self._texts: list[tuple[str, bool, Instance]] = []
        for inst in self.instances:
            fold = fold_case_for(inst)
            for root in roots_of(inst):
                ident = system.identity(root)
                if ident is not None and ident not in self._by_ident:
                    self._by_ident[ident] = inst
                for spelling in root_spellings(inst, root):
                    self._texts.append((spelling, fold, inst))
        self._cache: dict[str, Instance | None] = {}

    def by_prefix(self, prefix: str | None) -> Instance | None:
        """Return the instance whose prefix is exactly this text

        @param prefix  a prefix as an instance records it, or None
        @returns       the instance; None when no instance has that prefix
        """
        for inst in self.instances:
            if inst.prefix == prefix:
                return inst
        return None

    def by_identity(self, path: str) -> Instance | None:
        """Return the instance with an owned root at the path's realpath or above it, by file identity

        A case variant or the `/System/Volumes/Data` spelling therefore matches, and a string prefix never decides.

        @param path  an absolute path
        @returns     the instance; None for a relative path or when no ancestor is an owned root
        """
        if not path or not os.path.isabs(path):
            return None
        current = os.path.realpath(path)
        chain: list[str] = []
        result: Instance | None = None
        while True:
            if current in self._cache:
                result = self._cache[current]
                break
            chain.append(current)
            ident = system.identity(current)
            if ident is not None and ident in self._by_ident:
                result = self._by_ident[ident]
                break
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        for item in chain:
            self._cache[item] = result
        return result

    def by_text(self, text: str) -> Instance | None:
        """Return the instance whose longest owned-root spelling `text` lies under, for a prefix that may be gone

        @param text  a path as text
        @returns     the instance; None for a text that is not absolute or lies under no spelling
        """
        if not text or not text.startswith("/"):
            return None
        best: Instance | None = None
        best_len = -1
        for spelling, fold, inst in self._texts:
            if system.text_names_prefix(text, (spelling,), fold) and len(spelling) > best_len:
                best, best_len = inst, len(spelling)
        return best

    def owner(self, path: str) -> Instance | None:
        """Return the owning instance: by identity first, by text only when no existing ancestor decides

        @param path  an absolute path, which may be gone
        @returns     the instance; None when neither identity nor text names one
        """
        return self.by_identity(path) or self.by_text(path)

    def prefix_of(self, path: str | None) -> str | None:
        """Return the prefix of the instance that owns a path

        @param path  an absolute path, or None
        @returns     the prefix; None for no path or no owner
        """
        inst = self.owner(path) if path else None
        return inst.prefix if inst else None


# Text for `scan` ---------------------------------------------------------------

def _entry_note(entry: dict[str, Any]) -> str:
    """Return the note on a PATH entry: the prefix of the instance it names, and whether it is missing

    @param entry  a PATH entry of the environment scan
    @returns      the notes joined by commas; empty when there are none
    """
    notes = []
    if entry.get("instance_prefix"):
        notes.append(entry["instance_prefix"])
    if entry.get("exists") is False:
        notes.append("missing")
    return ", ".join(notes)


def _path_lines(environment: dict[str, Any]) -> list[str]:
    """Return the PATH section of the `scan` text: login shell, live PATH, lines naming a prefix, GUI PATH

    @param environment  the environment scan
    @returns            the section's lines, its title first
    """
    lines = ["PATH analysis"]
    login = environment.get("login_shell")
    if login:
        owner = environment.get("login_shell_prefix")
        provider = f"  (provided by {owner})" if owner else ""
        lines.append(f"  login shell  {login}{provider}")
    entries = (environment.get("live") or {}).get("PATH") or []
    duplicates = set((environment.get("live_duplicates") or {}).get("PATH") or [])
    rows = []
    for number, entry in enumerate(entries, 1):
        note = _entry_note(entry)
        if entry.get("text") in duplicates:
            note = (note + ", " if note else "") + "duplicate"
        rows.append((number, entry.get("text", ""), note))
    if rows:
        lines.extend("  " + line for line in table(rows, ("#", "live PATH entry", "note")))
    named = [r for r in environment.get("records") or [] if r.get("instance_prefixes") or r.get("kind") == "shellenv"]
    if named:
        lines.append("  shell file lines naming a prefix")
        for rec in named:
            what = rec.get("kind", "")
            if rec.get("var"):
                what += " " + rec["var"]
            if rec.get("position"):
                what += " " + rec["position"]
            if rec.get("block") is not None:
                what += " (MacPorts installer block)"
            prefixes = ", ".join(rec.get("instance_prefixes") or [])
            lines.append(f"    {rec.get('file')}:{rec.get('lineno')}  {what}  {prefixes}")
    etc = [e for e in environment.get("etc_paths") or [] if (e.get("entry") or {}).get("instance_prefix")]
    for item in etc:
        lines.append(f"  {item.get('file')}:{item.get('lineno')}  {item['entry'].get('text')}")
    gui = environment.get("gui_path")
    if gui:
        lines.append(f"  GUI PATH  {':'.join((e.get('text', '') for e in gui))}")
    return lines


def _shadow_lines(environment: dict[str, Any]) -> list[str]:
    """Return the shadowed-commands section of the `scan` text: what each command runs, who provides it

    @param environment  the environment scan
    @returns            the section's lines, its title first
    """
    shadowed = environment.get("shadowed") or []
    lines = ["Shadowed commands"]
    if not shadowed:
        return lines + ["  none"]
    rows = [(s.get("command"), s.get("winner") or "(not on PATH)", " ".join(s.get("prefixes") or []))
            for s in shadowed]
    return lines + ["  " + line for line in table(rows, ("command", "runs", "provided by"))]


def _linkage_lines(linkage: dict[str, Any]) -> list[str]:
    """Return the linkage section of the `scan` text: each reference of class other, usrlocal or missing

    @param linkage  the linkage scan
    @returns        the section's lines, its title first
    """
    lines = ["Cross-prefix linkage"]
    rows = []
    for path, report in sorted((linkage.get("binaries") or {}).items()):
        for ref in report.get("references") or []:
            if ref.get("class") in ("other", "usrlocal", "missing"):
                rows.append((report.get("package") or "", path, ref.get("class"), ref.get("name")))
    if not rows:
        lines.append(f"  no other, usrlocal or missing references in {len(linkage.get('binaries') or {})} binaries")
        return lines
    return lines + ["  " + line for line in table(rows, ("package", "binary", "class", "reference"))]


def _extras_lines(extras: dict[str, Any]) -> list[str]:
    """Return the extras section of the `scan` text: a count per kind and place of the interpreter extras

    @param extras  the interpreter extras scan: Python dists, pipx venvs, npm globals, gems and cpan modules
    @returns       the section's lines, its title first
    """
    lines = ["Interpreter extras"]
    rows = []
    for item in extras.get("python") or []:
        where = item.get("instance_prefix") or "user site"
        rows.append(("python" + item.get("version", ""), where, len(item.get("dists") or [])))
    for key, label in (("pipx", "pipx venvs"), ("npm", "npm globals"), ("gems", "gems"), ("cpan", "cpan modules")):
        counts: dict[str, int] = {}
        for item in extras.get(key) or []:
            where = item.get("instance_prefix") or "user"
            counts[where] = counts.get(where, 0) + 1
        for where, count in sorted(counts.items()):
            rows.append((label, where, count))
    if not rows:
        return lines + ["  none"]
    return lines + ["  " + line for line in table(rows, ("kind", "where", "count"))]


def _service_lines(services: Iterable[Service]) -> list[str]:
    """Return the services section of the `scan` text: each launchd job, its owner and its state

    @param services  the services the scan found
    @returns         the section's lines, its title first
    """
    rows = []
    for svc in services:
        state = "running" if svc.running else ("loaded" if svc.loaded else "not loaded")
        owner = (svc.package or "") if svc.owned else "user job"
        rows.append((svc.label, svc.instance_prefix, owner, state, svc.plist))
    if not rows:
        return ["Services", "  none"]
    return ["Services"] + ["  " + line for line in table(rows, ("label", "prefix", "package", "state", "plist"))]


def render(environment: dict[str, Any], linkage: dict[str, Any], extras: dict[str, Any],
           services: Iterable[Service] = ()) -> list[str]:
    """Render the `scan` text: PATH analysis, shadowed commands, cross-prefix linkage, extras and services

    @param environment  the environment scan; an empty one renders bare sections
    @param linkage      the linkage scan
    @param extras       the interpreter extras scan
    @param services     the services the scan found
    @returns            the lines, with a blank line between sections
    """
    lines: list[str] = []
    for part in (_path_lines(environment or {}), _shadow_lines(environment or {}),
                 _linkage_lines(linkage or {}), _extras_lines(extras or {}), _service_lines(services)):
        if lines:
            lines.append("")
        lines.extend(part)
    return lines

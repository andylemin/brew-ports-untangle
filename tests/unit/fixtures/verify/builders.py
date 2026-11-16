"""Builders for the verify tests: kegs and casks in a test's tree, `brew info` output and mappings

`Host` answers the verify probes, and `RecordingRunner` keeps the actions it ran.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Sequence
from typing import Any

from brew_ports import model, runner as runner_mod
from brew_ports.env import linkage
from brew_ports.model import Confidence, Package

THIN64 = b"\xcf\xfa\xed\xfe" + b"\x0c\x00\x00\x01" + b"\x00" * 24


def macho(path: str, mode: int = 0o755) -> str:
    """Write a file that starts with a thin 64-bit Mach-O header, making its parent directories

    @param path  the file
    @param mode  its permission bits
    @returns     the path
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(THIN64)
    os.chmod(path, mode)
    return path


def keg(prefix: str, name: str, version: str, *, exes: Sequence[str] = (), libs: Sequence[str] = (),
        link: bool = True) -> str:
    """Make `<prefix>/Cellar/<name>/<version>` with Mach-O `bin` and `lib` files and `opt/<name>` pointing at it

    @param prefix   the Homebrew prefix
    @param name     the formula
    @param version  the keg's version
    @param exes     the executables in its `bin`
    @param libs     the libraries in its `lib`
    @param link     whether `opt/<name>` points at the keg
    @returns        the keg's path
    """
    path = os.path.join(prefix, "Cellar", name, version)
    os.makedirs(path, exist_ok=True)
    for exe in exes:
        macho(os.path.join(path, "bin", exe))
    for lib in libs:
        macho(os.path.join(path, "lib", lib), 0o644)
    if link:
        opt = os.path.join(prefix, "opt", name)
        os.makedirs(os.path.dirname(opt), exist_ok=True)
        if os.path.lexists(opt):
            os.unlink(opt)
        os.symlink(path, opt)
    return path


def caskroom(prefix: str, token: str, version: str = "1.0") -> str:
    """Make a cask's Caskroom entry: a version directory and its `.metadata`

    @param prefix   the Homebrew prefix
    @param token    the cask token
    @param version  the installed version
    @returns        the Caskroom entry's path
    """
    room = os.path.join(prefix, "Caskroom", token)
    os.makedirs(os.path.join(room, version), exist_ok=True)
    os.makedirs(os.path.join(room, ".metadata", version, "20261113000000.000"), exist_ok=True)
    return room


def formula(name: str, versions: Sequence[str], *, linked: bool = True, keg_only: bool = False,
            deps: Sequence[str] = (), runtime: Sequence[str] = ()) -> dict[str, Any]:
    """Return one `formulae[]` entry of `brew info --json=v2 --installed`

    @param name      the formula
    @param versions  the installed versions, the newest last
    @param linked    whether the newest version is the linked keg
    @param keg_only  whether the formula is keg-only
    @param deps      the declared dependencies
    @param runtime   the receipts' `runtime_dependencies`, the same for every version
    @returns         the entry
    """
    installed = [{"version": v, "runtime_dependencies": [{"full_name": d, "version": "1"} for d in runtime]}
                 for v in versions]
    return {"name": name, "full_name": name, "aliases": [], "oldnames": [], "installed": installed,
            "linked_keg": versions[-1] if linked and versions else None, "keg_only": keg_only,
            "dependencies": list(deps)}


def cask(token: str, version: str = "1.0", artifacts: list[Any] | None = None) -> dict[str, Any]:
    """Return one `casks[]` entry of `brew info --json=v2 --installed`

    @param token      the cask token
    @param version    the installed version
    @param artifacts  the cask's `artifacts` list; None for none
    @returns          the entry
    """
    return {"token": token, "full_token": token, "installed": version, "artifacts": artifacts or []}


def info(formulae: Iterable[dict[str, Any]] = (), casks: Iterable[dict[str, Any]] = ()) -> str:
    """Return the output of `brew info --json=v2 --installed`

    @param formulae  the `formulae[]` entries
    @param casks     the `casks[]` entries
    @returns         the JSON text
    """
    return json.dumps({"formulae": list(formulae), "casks": list(casks)})


def mapping(source: Package, kind: str, name: str, *, version: str | None = None,
            companions: Sequence[str] = (), adopt: bool = False) -> model.Mapping:
    """Return an exact mapping of a source package, without selections

    @param source      the source package
    @param kind        the target kind, such as `formula`, `cask` or `pip`
    @param name        the target package
    @param version     the target version, or None
    @param companions  the extra target packages the mapping needs
    @param adopt       whether the target adopts the source cask
    @returns           the mapping
    """
    return model.Mapping(source=source, target_kind=kind, target_name=name, target_version=version,
                         confidence=Confidence.EXACT, evidence=["test"], companions=list(companions), selections=[],
                         variants_note=None, adopt=adopt)


def otool_sections(files: Sequence[str], refs: dict[str, list[tuple[str, str]]]) -> str:
    """Return `otool -l` text for a batch: each file with its load commands `(cmd, name)`

    @param files  the files of the batch, in order
    @param refs   the load commands of each file
    @returns      the text, one section per file
    """
    lines: list[str] = []
    for path in files:
        lines.append(f"{path}:")
        for number, (cmd, name) in enumerate(refs.get(path, [])):
            lines += [f"Load command {number}", f"          cmd {cmd}", "      cmdsize 56",
                      f"         name {name} (offset 24)"]
    return "\n".join(lines) + "\n"


class Host:
    """The host's answers: `brew info`, `brew missing`, `otool -l` from `refs`, pipx, the login shell, else exit 0

    `otool -l` prints no section for a file of `unreadable`, and exits 1 for a batch that holds one.
    """

    def __init__(self) -> None:
        """Answer as a host whose target holds nothing, with no pipx and a login PATH of `/usr/bin:/bin`"""
        self.info = info()
        self.missing = runner_mod.FakeResponse()
        self.refs: dict[str, list[tuple[str, str]]] = {}
        self.unreadable: set[str] = set()
        self.pipx: dict[str, Any] | None = None
        self.login = runner_mod.FakeResponse(stdout="/usr/bin:/bin\n")

    def __call__(self, key):
        """Answer one command

        @param key  the command's argv
        @returns    the response
        """
        words = list(key)
        if "info" in words and "--installed" in words:
            return runner_mod.FakeResponse(stdout=self.info)
        if words[-1] == "missing":
            return self.missing
        if words[0] == linkage.OTOOL:
            read = [w for w in words[2:] if w not in self.unreadable]
            return runner_mod.FakeResponse(exit=0 if len(read) == len(words) - 2 else 1,
                                           stdout=otool_sections(read, self.refs))
        if any(w.endswith("/bin/pipx") for w in words) and "list" in words:
            if self.pipx is None:
                return runner_mod.FakeResponse(exit=1, stderr="pipx: not found\n")
            return runner_mod.FakeResponse(stdout=json.dumps({"pipx_spec_version": "0.1", "venvs": self.pipx}))
        if words[0] == "/usr/bin/env":
            return self.login
        return runner_mod.FakeResponse()


class RecordingRunner(runner_mod.FakeRunner):
    """A FakeRunner that keeps every action it ran"""

    def __init__(self, **kwargs: Any) -> None:
        """Start a recording runner

        @param kwargs  the `FakeRunner` arguments
        """
        super().__init__(**kwargs)
        self.actions: list[model.Action] = []

    def run(self, action, defer_result=False):
        """Keep the action, then run it as `FakeRunner` does

        @param action        the action
        @param defer_result  whether the caller records the result itself
        @returns             the result
        """
        self.actions.append(action)
        return super().run(action, defer_result=defer_result)

"""Mach-O load command and rpath scan through `otool -l`, the tool's only link check

Unlike `brew linkage`, a developer command, it needs no `sudo` and tells cross-prefix references from system ones.
"""

from __future__ import annotations

import ctypes
import glob
import hashlib
import os
import re
import stat
import struct
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .. import system
from ..model import Instance, Package
from . import PrefixIndex

OTOOL = "/usr/bin/otool"
BATCH = 50
SYSTEM_ROOTS: tuple[str, ...] = ("/usr/lib", "/System")
USR_LOCAL = "/usr/local"

LOAD_COMMANDS = ("LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LOAD_UPWARD_DYLIB")
WEAK = "LC_LOAD_WEAK_DYLIB"
CLASSES = ("variable", "unresolved", "missing", "weak", "own", "other", "usrlocal", "system", "external")
BROKEN = ("missing", "other", "usrlocal")      # what the linkage findings act on; MacPorts' only `missing`

_THIN = (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
_FAT = (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
_MAX_FAT_ARCHS = 30
_KEG_FLAT = ("bin", "sbin")
_KEG_DEEP = ("lib", "libexec", "Frameworks")

_NAME_RE = re.compile(r"^name (.*) \(offset \d+\)$")
_PATH_RE = re.compile(r"^path (.*) \(offset \d+\)$")
_ARCH_RE = re.compile(r"^(.*) \(architecture ([^()\s]+)\)$")
_NOT_OBJECT = ": is not an object file"


# Which files are Mach-O ----------------------------------------------------------

def is_macho(path: str) -> bool:
    """Return whether a file starts with a thin Mach-O magic, or a fat magic followed by at most 30 architectures

    A Java class file shares the `cafebabe` magic and carries its version there; `*.class` files are skipped.

    @param path  a regular file
    @returns     True for a Mach-O file; False for a `*.class` file or one that cannot be read
    """
    if path.endswith(".class"):
        return False
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    if head[:4] in _THIN:
        return True
    if head[:4] in _FAT and len(head) == 8:
        return struct.unpack(">I", head[4:8])[0] <= _MAX_FAT_ARCHS
    return False


def _regular(path: str) -> os.stat_result | None:
    """Return the `lstat` result of a regular file

    @param path  a path, which is not followed when it is a symlink
    @returns     the result; None for a symlink, a directory or another special file, or when `lstat` fails
    """
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return st if stat.S_ISREG(st.st_mode) else None


def keg_binaries(keg: str) -> list[str]:
    """List the Mach-O regular files in `<keg>/bin`, `<keg>/sbin` and below `lib`, `libexec` and `Frameworks`

    The recursive glob also walks symlinked directories (a framework's `Versions/Current`), so each
    inode is kept once, under the first name in sorted order.

    @param keg  a keg, `<prefix>/Cellar/<name>/<version>`
    @returns    the binaries' paths, sorted
    """
    base = glob.escape(keg)
    candidates: list[str] = []
    for sub in _KEG_FLAT:
        candidates.extend(glob.glob(os.path.join(base, sub, "*")))
    for sub in _KEG_DEEP:
        candidates.extend(glob.glob(os.path.join(base, sub, "**"), recursive=True))
    out: list[str] = []
    seen = set()
    for path in sorted(set(candidates)):
        st = _regular(path)
        if st is None or (st.st_dev, st.st_ino) in seen:
            continue
        if is_macho(path):
            seen.add((st.st_dev, st.st_ino))
            out.append(path)
    return out


# The scan set -------------------------------------------------------------------

def scan_set(packages: Iterable[Package], deep: bool, dependents_of: Iterable[str] = ()) -> list[Package]:
    """Choose the packages whose binaries the linkage scan reads

    Active ports, and the formulae not poured from a bottle or without a receipt.

    @param packages       the inventoried packages
    @param deep           whether to read every formula, bottled ones included
    @param dependents_of  names whose dependent formulae and ports are read too, bottled or inactive ones included
    @returns              the packages to scan, in the order given
    """
    upgraded = set(dependents_of)
    out: list[Package] = []
    for pkg in packages:
        if upgraded and upgraded.intersection(pkg.deps) and pkg.kind in ("formula", "port"):
            out.append(pkg)
        elif pkg.kind == "port":
            if pkg.active:
                out.append(pkg)
        elif pkg.kind == "formula":
            # A receipt without `poured_from_bottle` leaves built_locally None: scanned.
            if deep or not pkg.receipt_ok or pkg.built_locally is not False:
                out.append(pkg)
    return out


def package_key(pkg: Package) -> str:
    """Return the key of a package in the linkage report

    @param pkg  an inventoried package
    @returns    `<prefix>|<kind>|<name>`
    """
    return f"{pkg.instance_prefix}|{pkg.kind}|{pkg.name}"


def formula_keg(pkg: Package) -> str:
    """Return the keg of a formula's installed version

    @param pkg  an inventoried formula
    @returns    `<prefix>/Cellar/<name>/<version>`
    """
    return os.path.join(pkg.instance_prefix, "Cellar", pkg.name, pkg.version)


def binaries_by_package(packages: Iterable[Package]) -> dict[str, list[str]]:
    """Map each package to its `binaries`

    A formula whose inventory left them empty gets `keg_binaries` of its keg; a port keeps what the
    registry lists (`files.binary = 1 AND active = 1`).

    @param packages  the packages to scan
    @returns         the binaries by `package_key`
    """
    out: dict[str, list[str]] = {}
    for pkg in packages:
        binaries = list(pkg.binaries)
        if not binaries and pkg.kind == "formula":
            binaries = keg_binaries(formula_keg(pkg))
        out[package_key(pkg)] = binaries
    return out


# The dyld shared cache ----------------------------------------------------------

_CACHE_LOOKUP: dict[str, Any] = {}


def _cache_function() -> Callable[[bytes], bool] | None:
    """Return libSystem's `_dyld_shared_cache_contains_path()`, looked up once

    @returns  the function; None off macOS, without libSystem, or on a macOS without the call
    """
    if "fn" not in _CACHE_LOOKUP:
        _CACHE_LOOKUP["fn"] = None
        if sys.platform == "darwin":
            try:
                try:
                    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
                except OSError:
                    lib = ctypes.CDLL(None)
                fn = getattr(lib, "_dyld_shared_cache_contains_path", None)   # None on a macOS without the call
                if fn is not None:
                    fn.argtypes = [ctypes.c_char_p]
                    fn.restype = ctypes.c_bool
                    _CACHE_LOOKUP["fn"] = fn
            except OSError:  # no libSystem
                _CACHE_LOOKUP["fn"] = None
    return _CACHE_LOOKUP["fn"]


def shared_cache_contains(path: str) -> bool:
    """Return whether the dyld shared cache holds `path`; False off macOS and when the lookup fails

    macOS 11 and newer keep the system libraries only in that cache; libSystem's
    `_dyld_shared_cache_contains_path()` answers through `ctypes`.

    @param path  the library
    @returns     whether the cache holds it
    """
    fn = _cache_function()
    if fn is None:
        return False
    try:
        return bool(fn(os.fsencode(path)))
    except (ctypes.ArgumentError, OSError, TypeError, ValueError):  # a path fsencode or ctypes refuses; a failed call
        return False


# Parsing `otool -l` -------------------------------------------------------------

@dataclass
class Section:
    """One file, or one architecture of a fat file, in `otool -l` output"""

    file: str
    arch: str | None
    references: list[tuple[str, str]] = field(default_factory=list)   # (load command, name)
    rpaths: list[str] = field(default_factory=list)


def _header(line: str, files: dict[str, None]) -> tuple[str | None, str | None]:
    """Return the file and architecture a section header of `otool -l` names

    @param line   an unindented line that ends in a colon
    @param files  the files of the batch
    @returns      the file and its architecture, None for a thin file; two Nones when no file of the batch matches
    """
    head = line[:-1]
    if head in files:
        return head, None
    m = _ARCH_RE.match(head)
    if m and m.group(1) in files:
        return m.group(1), m.group(2)
    return None, None


def parse_otool(text: str, files: Sequence[str]) -> tuple[dict[str, list[Section]], dict[str, str]]:
    """Parse `otool -l` output into the sections of each file of the batch and the files reported as errors

    A section starts at `<file>:` or `<file> (architecture <arch>):`; another unindented `/...:` line (an
    archive member) starts an ignored one. `LC_ID_DYLIB`, a dylib's own install name, is no reference.

    @param text   the output of one batch
    @param files  the files of the batch
    @returns      the sections by file, and the error by file for each file `otool` reports as no object file
    """
    known = dict.fromkeys(files)
    sections: dict[str, list[Section]] = {}
    errors: dict[str, str] = {}
    current: Section | None = None
    command: str | None = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            if line.endswith(_NOT_OBJECT) and line[:-len(_NOT_OBJECT)] in known:
                errors[line[:-len(_NOT_OBJECT)]] = "not an object file"
                current, command = None, None
                continue
            if line.endswith(":"):
                name, arch = _header(line, known)
                if name is not None:
                    current = Section(name, arch)
                    sections.setdefault(name, []).append(current)
                    command = None
                    continue
                if line.startswith("/"):
                    current, command = None, None   # a section of another file: an archive member
                    continue
            if line.startswith("Load command "):
                command = None
                continue
        if current is None:
            continue
        body = line.strip()
        if body.startswith("cmd "):
            command = body[4:].strip()
            continue
        if command in LOAD_COMMANDS:
            m = _NAME_RE.match(body)
            if m:
                current.references.append((command, m.group(1)))
        elif command == "LC_RPATH":
            m = _PATH_RE.match(body)
            if m:
                current.rpaths.append(m.group(1))
    return sections, errors


# Classification -----------------------------------------------------------------

def _strip_data_volume(path: str) -> str:
    """Return a path without a leading `/System/Volumes/Data`

    @param path  a normalised absolute path
    @returns     the path as the root volume spells it; `/` for the Data volume itself
    """
    if path == system.DATA_VOLUME or path.startswith(system.DATA_VOLUME + "/"):
        return path[len(system.DATA_VOLUME):] or "/"
    return path


def _under_roots(path: str, roots: Sequence[str]) -> bool:
    """Return whether a path, compared as text, is one of the roots or lies below one

    @param path   an absolute path; it is normalised and loses a leading `/System/Volumes/Data` first
    @param roots  directories such as `SYSTEM_ROOTS`
    @returns      True when the path is a root or lies below one
    """
    path = _strip_data_volume(os.path.normpath(path))
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


class _Classifier:
    """The class of one reference of one binary, one of `CLASSES`"""

    def __init__(self, instances: Sequence[Instance], in_shared_cache: Callable[[str], bool],
                 system_roots: Sequence[str], usr_local: str) -> None:
        """Index the instances' prefixes and take the identity of `/usr/local`

        @param instances        the instances, whose prefixes decide `own` and `other`
        @param in_shared_cache  returns whether the dyld shared cache holds a path
        @param system_roots     the directories whose libraries may exist only in that cache
        @param usr_local        the directory whose references are `usrlocal`, unless the binary's instance lives there
        """
        self.index = PrefixIndex(instances)
        self.in_shared_cache = in_shared_cache
        self.system_roots = tuple(system_roots)
        self.usr_local = system.identity(usr_local)
        self._exists: dict[str, bool] = {}

    def exists(self, path: str) -> bool:
        """Return whether a library is on disk, or for `/usr/lib` and `/System` in the dyld shared cache

        @param path  a resolved reference
        @returns     True when it is present; each answer is cached
        """
        found = self._exists.get(path)
        if found is None:
            found = os.path.exists(path) or (_under_roots(path, self.system_roots) and self.in_shared_cache(path))
            self._exists[path] = found
        return found

    def resolve(self, binary: str, name: str, rpaths: Sequence[str]) -> tuple[str | None, str | None]:
        """Resolve the path a load command names, or return the class that ends the decision

        @param binary  the binary that holds the load command
        @param name    the install name the command gives
        @param rpaths  the binary's `LC_RPATH` entries, in order
        @returns       the path and None; or None and `variable` or `unresolved`
        """
        if name.startswith("@executable_path"):
            return None, "variable"
        if name.startswith("@loader_path"):
            return os.path.join(os.path.dirname(binary), name[len("@loader_path"):].lstrip("/")), None
        if name.startswith("@rpath"):
            rest = name[len("@rpath"):].lstrip("/")
            for rpath in rpaths:
                if rpath.startswith("@loader_path"):
                    base = os.path.join(os.path.dirname(binary), rpath[len("@loader_path"):].lstrip("/"))
                elif rpath.startswith("@"):
                    continue     # @executable_path: the executable that loads this file decides
                else:
                    base = rpath
                candidate = os.path.join(base, rest)
                if self.exists(candidate):
                    return candidate, None
            return None, "unresolved"
        if name.startswith("@") or not name.startswith("/"):
            return None, "variable"   # another token, or a name dyld looks up from the working directory
        return name, None

    def by_prefix(self, binary_owner: Instance | None, path: str) -> str:
        """Return the class of a library that exists, by where its realpath lies

        @param binary_owner  the instance that owns the binary, or None
        @param path          the resolved reference
        @returns             `own`, `other`, `usrlocal`, `system` or `external`
        """
        real = os.path.realpath(path)
        owner = self.index.by_identity(real)
        if owner is not None:
            return "own" if owner is binary_owner else "other"
        if self.usr_local is not None and system.lies_under(real, self.usr_local):
            at_usr_local = binary_owner is not None and system.identity(binary_owner.prefix) == self.usr_local
            return "external" if at_usr_local else "usrlocal"
        if _under_roots(path, self.system_roots) or _under_roots(real, self.system_roots):
            return "system"
        return "external"

    def classify(self, binary: str, command: str, name: str, rpaths: Sequence[str]) -> dict[str, Any]:
        """Return the reference, resolved, with its class

        In order: `variable`; `unresolved` (an `@rpath` with no existing match); `missing`, or `weak` for
        `LC_LOAD_WEAK_DYLIB`; then `own`, `other`, `usrlocal`, `system` by prefix, else `external`.

        @param binary   the binary that holds the load command
        @param command  the load command, one of `LOAD_COMMANDS`
        @param name     the install name it gives
        @param rpaths   the binary's `LC_RPATH` entries, in order
        @returns        the `name`, `command`, `resolved` path and `class`; the path is a realpath once it exists
        """
        path, cls = self.resolve(binary, name, rpaths)
        if cls is None and path is not None:
            if not self.exists(path):
                cls = "weak" if command == WEAK else "missing"
            else:
                cls = self.by_prefix(self.index.by_identity(binary), path)
        shown = os.path.realpath(path) if path and cls not in ("missing", "weak") else (
            os.path.normpath(path) if path else None)
        return {"name": name, "command": command, "resolved": shown, "class": cls}


# The scan -----------------------------------------------------------------------

def _batch_id(batch: Sequence[str]) -> str:
    """Return the action id of one `otool` batch, which a digest of its files keeps unique

    @param batch  the files of the batch
    @returns      `0.linkage.<digest>.otool`
    """
    digest = hashlib.sha1("\0".join(batch).encode("utf-8", "surrogateescape")).hexdigest()[:12]
    return f"0.linkage.{digest}.otool"


def _batches(files: Sequence[str], size: int) -> list[list[str]]:
    """Split the files into the batches of one `otool` command each

    @param files  the binaries, in scan order
    @param size   the most files a batch holds
    @returns      the batches, in order
    """
    return [list(files[i:i + size]) for i in range(0, len(files), size)]


def scan(runner, package_binaries: dict[str, list[str]], instances: Sequence[Instance], *,
         batch_size: int = BATCH, in_shared_cache: Callable[[str], bool] | None = None,
         system_roots: Sequence[str] = SYSTEM_ROOTS, usr_local: str = USR_LOCAL) -> dict[str, Any]:
    """Scan the binaries with `otool -l` in batches and class every reference

    A batch that exits non-zero (a file vanished) is still parsed; a file with no section in the output
    gets an error.

    @param runner            the runner of the `otool` probes
    @param package_binaries  the binaries by package key; a binary listed twice counts for the first package
    @param instances         the instances, whose prefixes decide `own` and `other`
    @param batch_size        the most files one `otool` command reads
    @param in_shared_cache   returns whether the dyld shared cache holds a path; None for `shared_cache_contains`
    @param system_roots      the directories whose libraries may exist only in that cache
    @param usr_local         the directory whose references are `usrlocal`
    @returns                 the `binaries`, `packages`, `classes` and `errors`, as `_summary` builds them
    """
    check = in_shared_cache or shared_cache_contains
    classifier = _Classifier(instances, check, system_roots, usr_local)
    owner_key: dict[str, str] = {}
    order: list[str] = []
    for key, files in package_binaries.items():
        for path in files:
            if path not in owner_key:
                owner_key[path] = key
                order.append(path)
    binaries: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for batch in _batches(order, max(1, batch_size)):
        action = system.probe(_batch_id(batch), [OTOOL, "-l"] + batch, f"Mach-O load commands of {len(batch)} files")
        try:
            result = runner.run(action)
            text, code, timed_out = result.stdout(), result.exit, result.timed_out
        except OSError as exc:
            text, code, timed_out = "", 127, False
            errors.append(f"otool could not run: {exc}")
        if code != 0:
            note = " (timed out)" if timed_out else ""
            errors.append(f"otool -l exited {code}{note} for {len(batch)} files starting with {batch[0]}")
        sections, failed = parse_otool(text, batch)
        for path in batch:
            binaries[path] = _binary_report(classifier, path, owner_key[path], sections.get(path, []),
                                            failed.get(path) or (None if path in sections else "no otool output"))
    return _summary(binaries, package_binaries, errors)


def _binary_report(classifier: _Classifier, path: str, key: str, sections: list[Section],
                   error: str | None) -> dict[str, Any]:
    """Return the linkage report of one binary: its classed references, its architectures and its error

    @param classifier  classes the references
    @param path        the binary
    @param key         the package key the binary is scanned for
    @param sections    the binary's sections in the `otool -l` output, one per architecture of a fat file
    @param error       why the output holds no section of the binary, or None
    @returns           the `package`, `instance_prefix`, `archs`, `references` and `error`
    """
    owner = classifier.index.by_identity(path)
    refs: list[dict[str, Any]] = []
    for section in sections:
        for command, name in section.references:
            ref = classifier.classify(path, command, name, section.rpaths)
            ref["arch"] = section.arch
            refs.append(ref)
    return {"package": key, "instance_prefix": owner.prefix if owner else None,
            "archs": [s.arch for s in sections if s.arch], "references": refs, "error": error}


def _summary(binaries: dict[str, dict[str, Any]], package_binaries: dict[str, list[str]],
             errors: list[str]) -> dict[str, Any]:
    """Return the result of a linkage scan: each binary's report, a summary per package and the totals

    A package's `broken` lists its binaries with a reference in a `BROKEN` class; a count of 0 is left out.

    @param binaries          the report of each binary
    @param package_binaries  the binaries by package key
    @param errors            the failures of the `otool` batches
    @returns                 the `binaries`, `packages`, `classes` and `errors`
    """
    totals = dict.fromkeys(CLASSES, 0)
    packages: dict[str, dict[str, Any]] = {}
    for key, files in package_binaries.items():
        counts = dict.fromkeys(CLASSES, 0)
        broken: list[str] = []
        for path in files:
            report = binaries.get(path)
            if report is None or report["package"] != key:
                continue
            classes = [r["class"] for r in report["references"]]
            for cls in classes:
                counts[cls] += 1
                totals[cls] += 1
            if any(c in BROKEN for c in classes):
                broken.append(path)
        packages[key] = {"binaries": len(files), "classes": {k: v for k, v in counts.items() if v},
                         "broken": broken}
    return {"binaries": binaries, "packages": packages,
            "classes": {k: v for k, v in totals.items() if v}, "errors": errors}


def references(report: dict[str, Any], classes: Iterable[str]) -> list[tuple[str, str, dict[str, Any]]]:
    """Return every reference of the given classes, with its package key and binary

    @param report   the result of a linkage scan
    @param classes  the classes wanted, from `CLASSES`
    @returns        `(package key, binary, reference)` tuples, in binary path order
    """
    wanted = set(classes)
    out = []
    for path, item in sorted((report.get("binaries") or {}).items()):
        for ref in item.get("references") or []:
            if ref.get("class") in wanted:
                out.append((item.get("package"), path, ref))
    return out

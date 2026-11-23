"""The architectures in a Mach-O header, and the libraries that lack one their binary has"""

from __future__ import annotations

import struct
from collections.abc import Mapping, Sequence
from typing import Any

_CPU_TYPES = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32",
              18: "ppc", 0x01000012: "ppc64"}
_THIN_BE = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf")
_THIN_LE = (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
_FAT_ENTRY_SIZE = {b"\xca\xfe\xba\xbe": 20, b"\xca\xfe\xba\xbf": 32}
_MAX_FAT_ARCHS = 30


def macho_archs(path: str) -> frozenset[str] | None:
    """Return the architectures in a Mach-O header

    A thin file has one cputype and a fat one several; more than 30 entries is a Java class file.

    @param path  the file
    @returns     the architecture names; None for a file that is no Mach-O or cannot be read
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
            if len(head) < 8:
                return None
            magic = head[:4]
            if magic in _THIN_BE:
                cpus = [struct.unpack(">i", head[4:8])[0]]
            elif magic in _THIN_LE:
                cpus = [struct.unpack("<i", head[4:8])[0]]
            elif magic in _FAT_ENTRY_SIZE:
                count = struct.unpack(">I", head[4:8])[0]
                size = _FAT_ENTRY_SIZE[magic]
                if count > _MAX_FAT_ARCHS:
                    return None
                table = fh.read(count * size)
                if len(table) < count * size:
                    return None
                cpus = [struct.unpack(">i", table[i * size:i * size + 4])[0] for i in range(count)]
            else:
                return None
    except OSError:
        return None
    return frozenset(_CPU_TYPES.get(cpu, f"cpu{cpu}") for cpu in cpus)


def arch_gaps(binary: str, references: Sequence[Mapping[str, Any]], wanted: set[str],
              cache: dict[str, frozenset[str] | None] | None = None) -> list[str]:
    """Return each "missing arch inside the prefix", as `rev-upgrade` decides it

    A library the binary loads from its own prefix (an `own` reference) lacks one of the binary's
    architectures. Only the architectures the host or the instance runs are checked.

    @param binary      the binary
    @param references  the binary's linkage references, with their `class` and `resolved` path
    @param wanted      the architectures to check, the host's and the instance's
    @param cache       the architectures of each path read so far, shared across calls; None for a fresh one
    @returns           one `<library>, which has no <archs> code` phrase per gap
    """
    cache = {} if cache is None else cache

    def archs(path: str) -> frozenset[str] | None:
        if path not in cache:
            cache[path] = macho_archs(path)
        return cache[path]

    have = archs(binary)
    need = set(have or ()) & wanted
    if not need:
        return []
    out: list[str] = []
    for ref in references:
        lib = ref.get("resolved")
        if ref.get("class") != "own" or not lib:
            continue
        lib_archs = archs(lib)
        if lib_archs is None:
            continue
        lacking = sorted(need - lib_archs)
        gap = f"{lib}, which has no {' or '.join(lacking)} code"
        if lacking and gap not in out:
            out.append(gap)
    return out

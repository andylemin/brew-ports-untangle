"""Locating MacPorts instances and deciding whether each can be driven"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass

from .. import system
from ..model import Instance, Manager, Usability
from ..state import slug
from . import actions, registry

DEFAULT_PREFIX = "/opt/local"
ETC_PATHS = "/etc/paths"
CONF_REL = os.path.join("etc", "macports", "macports.conf")
AUTOCONF_REL = os.path.join("libexec", "macports", "lib", "macports1.0", "macports_autoconf.tcl")
TCLSH_REL = os.path.join("libexec", "macports", "bin", "tclsh8.6")
LIPO = system.LIPO
PKG_ID = "org.macports.MacPorts"
PLATFORM_TEXTS = ("does not match expected platform", "should be rebuilt for Apple Silicon")
INTEL_ON_ARM = "MacPorts runs as Intel code on this Apple Silicon Mac"
READONLY_TEXT = "attempt to write a readonly database"

# Base's own files besides its package receipt, never counted as unregistered.
BASE_TREES = ("libexec/macports", "share/macports", "etc/macports", "var/macports")
BASE_PROGRAMS = ("port", "portf", "portindex", "portmirror", "daemondo", "port-tclsh")
BASE_MAN_PAGES = ("share/man/man1/port*.1.gz", "share/man/man5/macports.conf.5.gz", "share/man/man7/port*.7.gz")

Platform = tuple[str, int]


class TargetRefused(ValueError):
    """`--target-prefix` names an instance that cannot be a `ports` target"""


# Configuration --------------------------------------------------------------

_CONF_RE = re.compile(r"^(\w+)(?:[ \t]+(.*))?$")
_AUTOCONF_RE = re.compile(r'^\s*variable\s+(\w+)\s+"([^"]*)"', re.MULTILINE)


def _read_text(path: str) -> str | None:
    """Return the text of a file, undecodable bytes replaced

    @param path  the file
    @returns     the text; None when the file cannot be read
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def parse_conf(path: str) -> dict[str, str]:
    """Parse the `key value` lines of a macports.conf as base reads them

    A line is `^(\\w+)([ \\t]+(.*))?$`, so `#` comments and indented lines
    are no keys; a trailing backslash continues the value on the next line.

    @param path  the macports.conf
    @returns     the value of each key, the last line of a key winning; empty when the file cannot be read
    """
    text = _read_text(path)
    out: dict[str, str] = {}
    if text is None:
        return out
    key: str | None = None
    continuation = False
    for raw in text.splitlines():
        continues = raw.endswith("\\")
        line = raw[:-1] if continues else raw
        if continuation:
            if key is not None:
                out[key] = (out[key] + " " + line.strip()).strip()
        else:
            match = _CONF_RE.match(line)
            if not match:
                continue
            key = match.group(1)
            out[key] = (match.group(2) or "").strip()
        continuation = continues
    return out


def _home(environ: Mapping[str, str]) -> str:
    """Return the user's home directory

    @param environ  the environment
    @returns        its `HOME`, else the home `~` expands to
    """
    return environ.get("HOME") or os.path.expanduser("~")


def read_config(prefix: str, environ: Mapping[str, str]) -> dict[str, str]:
    """Read `<prefix>/etc/macports/macports.conf`, then the user's `~/.macports/macports.conf`

    The user's file overrides the prefix's for the user's `port` runs, and both override the documented
    defaults.

    @param prefix   the MacPorts prefix
    @param environ  the environment, whose `HOME` holds the user's file
    @returns        the settings; `prefix`, `portdbpath`, `applications_dir`, `frameworks_dir` and
                    `sources_conf` always among them
    """
    conf = {
        "prefix": prefix,
        "portdbpath": os.path.join(prefix, "var", "macports"),
        "applications_dir": "/Applications/MacPorts",
        "frameworks_dir": os.path.join(prefix, "Library", "Frameworks"),
        "sources_conf": os.path.join(prefix, "etc", "macports", "sources.conf"),
    }
    conf.update(parse_conf(os.path.join(prefix, CONF_REL)))
    user_dir = os.path.join(_home(environ), ".macports")
    if os.path.isdir(user_dir):
        conf.update(parse_conf(os.path.join(user_dir, "macports.conf")))
    return conf


def read_autoconf(prefix: str) -> dict[str, str]:
    """Read the `variable <name> "<value>"` lines of `macports_autoconf.tcl`

    @param prefix  the MacPorts prefix
    @returns       the value of each variable, `macports_version`, `os_platform` and `os_major` among them;
                   empty when the file cannot be read
    """
    text = _read_text(os.path.join(prefix, AUTOCONF_REL))
    return dict(_AUTOCONF_RE.findall(text)) if text else {}


def decode_pkg_version(info: str) -> str | None:
    """Decode the `version:` line of `pkgutil --pkg-info`: `0.2.8.1.0.0.0.0.0` is 2.8.1

    The leading `0.` goes, then trailing `.0` groups until three groups remain.

    @param info  the output of `pkgutil --pkg-info`
    @returns     the base version; None without a `version:` line in that form
    """
    for line in info.splitlines():
        key, _, value = line.partition(":")
        if key.strip() != "version":
            continue
        groups = value.strip().split(".")
        if len(groups) < 2 or groups[0] != "0" or not all(g.isdigit() for g in groups):
            return None
        groups = groups[1:]
        while len(groups) > 3 and groups[-1] == "0":
            groups.pop()
        return ".".join(groups)
    return None


def features_for(version: str | None) -> tuple[str, ...]:
    """Return the features of a base version: `migrate` and `snapshot` from 2.10.0, `snapshot_export` from 2.11.0

    @param version  the base version, or None when it is unknown
    @returns        the features; none for an unknown version
    """
    if not version:
        return ()
    out: list[str] = []
    if registry.vercmp(version, "2.10.0") >= 0:
        out += ["migrate", "snapshot"]
    if registry.vercmp(version, "2.11.0") >= 0:
        out.append("snapshot_export")
    return tuple(out)


def running_platform() -> Platform:
    """Return the `uname` platform and Darwin major that base compares its own build with

    @returns  the lower-cased system name and the major release; 0 for a release that does not start with a number
    """
    uname = os.uname()
    try:
        major = int(uname.release.split(".")[0])
    except ValueError:
        major = 0
    return uname.sysname.lower(), major


# Probes -----------------------------------------------------------------------

def arch_from_lipo(text: str, host_arch: str) -> str | None:
    """Return the architecture `port` runs as: a file holding the host's architecture counts as the host's

    @param text       the output of `lipo -archs`
    @param host_arch  the host's architecture
    @returns          arm64 or x86_64; None when `lipo` names neither
    """
    archs = text.split()
    if host_arch in archs:
        return host_arch
    for word in archs:
        if word.startswith("arm64"):
            return "arm64"
        if word.startswith("x86_64"):
            return "x86_64"
    return None


def instance_arch(runner, prefix: str, host_arch: str) -> str | None:
    """Probe `lipo -archs` of base's `tclsh8.6`, the interpreter `port` runs under

    @param runner     the runner that runs `lipo`
    @param prefix     the MacPorts prefix
    @param host_arch  the host's architecture
    @returns          arm64 or x86_64; None without the interpreter or a `lipo` answer
    """
    tclsh = os.path.join(prefix, TCLSH_REL)
    if not os.path.exists(tclsh):
        return None
    result = runner.run(system.probe(f"0.ports.{slug(prefix)}.lipo", [LIPO, "-archs", tclsh],
                                     f"architecture of MacPorts base at {prefix}"))
    return arch_from_lipo(result.stdout(), host_arch) if result.exit == 0 else None


def package_version(runner) -> str | None:
    """Probe the base version recorded by the installer package's receipt

    @param runner  the runner that runs `pkgutil`
    @returns       the version; None without a receipt
    """
    result = runner.run(system.probe("0.ports.receipt.info", [system.PKGUTIL, "--pkg-info", PKG_ID],
                                     "MacPorts installer receipt"))
    return decode_pkg_version(result.stdout()) if result.exit == 0 else None


def receipt_files(runner) -> frozenset[str]:
    """Probe `pkgutil --files org.macports.MacPorts`, with `/` prepended

    @param runner  the runner that runs `pkgutil`
    @returns       the absolute paths of the receipt's files; empty without a receipt
    """
    result = runner.run(system.probe("0.ports.receipt.files", [system.PKGUTIL, "--files", PKG_ID],
                                     "files of the MacPorts installer receipt"))
    if result.exit != 0:
        return frozenset()
    return frozenset("/" + line.strip().lstrip("/") for line in result.stdout().splitlines() if line.strip())


@dataclass(frozen=True)
class BaseFiles:
    """Base's own files in a prefix, never unregistered strays

    They are the installer receipt's files, everything under `libexec/macports`, `share/macports`,
    `etc/macports` and `var/macports`, the base programs and the base man pages.
    """

    prefix: str
    receipt: frozenset[str] = frozenset()

    @classmethod
    def load(cls, runner, prefix: str) -> "BaseFiles":
        """Return base's files in a prefix, the receipt probed with `pkgutil`

        @param runner  the runner that runs `pkgutil`
        @param prefix  the MacPorts prefix
        @returns       the base files
        """
        return cls(prefix, receipt_files(runner))

    def owns(self, path: str) -> bool:
        """Return whether `path` belongs to MacPorts base: its receipt, base trees, programs or man pages

        @param path  an absolute path
        @returns     True for a file of base
        """
        path = os.path.normpath(path)
        if path in self.receipt:
            return True
        prefix = os.path.normpath(self.prefix)
        if not path.startswith(prefix.rstrip("/") + "/"):
            return False
        rel = path[len(prefix.rstrip("/")) + 1:]
        if any(rel.startswith(tree + "/") for tree in BASE_TREES):
            return True
        if rel in ["bin/" + name for name in BASE_PROGRAMS]:
            return True
        return any(fnmatch.fnmatchcase(rel, pattern) for pattern in BASE_MAN_PAGES)


def _walk_files(top: str) -> Iterator[str]:
    """Yield every entry below `top` that is not a real directory, symlinks included

    @param top       the directory to walk
    @returns         an iterator over the paths; empty for a missing `top`
    @throws OSError  `top` or a directory below it cannot be read, so an unreadable tree never reads as empty
    """
    try:
        with os.scandir(top) as it:
            entries = list(it)
    except FileNotFoundError:
        return
    for entry in entries:
        if entry.is_dir(follow_symlinks=False):
            yield from _walk_files(entry.path)
        else:
            yield entry.path


def known_empty(prefix: str, portdbpath: str, base: BaseFiles) -> bool:
    """Return whether a prefix without `registry.db` holds no port

    It holds none when `<portdbpath>/software/` has no image and `bin`, `sbin` and `lib` hold nothing but
    base's own files.

    @param prefix      the MacPorts prefix
    @param portdbpath  the instance's `portdbpath`
    @param base        base's own files in the prefix
    @returns           True for an empty prefix; False for a trace of a port or a tree the user cannot read
    """
    try:
        if registry.image_archives(portdbpath):
            return False
        for sub in ("bin", "sbin", "lib"):
            if any(not base.owns(path) for path in _walk_files(os.path.join(prefix, sub))):
                return False
    except OSError:
        return False
    return True


# Usability ------------------------------------------------------------------------

def release(platform: str, major: str) -> str:
    """Return a platform and its major as the report names them

    @param platform  the `uname` system name in lower case, or empty when it is not recorded
    @param major     the major release, or empty when it is not recorded
    @returns         the macOS release of a Darwin major; else the two words, `?` for one that is not recorded
    """
    if platform in ("", "darwin") and major.isdigit():
        return system.macos_name(int(major))
    return f"{platform or '?'} {major or '?'}"


def platform_mismatch(autoconf: Mapping[str, str], running: Platform, arch: str | None, host_arch: str,
                      stderr: str) -> str | None:
    """Return the PLATFORM_MISMATCH reason

    Base built for another platform or Darwin major, an x86_64 base on an arm64 host (a base older than
    2.10 prints no Apple Silicon warning), or base's own platform error text.

    @param autoconf   the variables of `macports_autoconf.tcl`
    @param running    the running platform and its Darwin major
    @param arch       the architecture `port` runs as, or None when unknown
    @param host_arch  the host's architecture
    @param stderr     the standard error of `port version`
    @returns          the reason; None when base matches the host
    """
    built = (autoconf.get("os_platform") or "", autoconf.get("os_major") or "")
    if (built[0] and built[0] != running[0]) or (built[1] and built[1] != str(running[1])):
        return f"MacPorts was built for {release(*built)}; this Mac runs {release(running[0], str(running[1]))}"
    if host_arch == "arm64" and arch == "x86_64":
        return INTEL_ON_ARM
    for line in stderr.splitlines():
        if any(text in line for text in PLATFORM_TEXTS):
            return line.strip()
    return None


def _error_text(stderr: str, exit_code: int | None) -> str:
    """Return the detail of a failed `port version`: its non-blank stderr lines joined, cut at 1000 characters

    @param stderr     the standard error
    @param exit_code  the exit status, for the detail of a run that printed nothing
    @returns          the detail
    """
    text = "; ".join(line.strip() for line in stderr.splitlines() if line.strip())
    return text[:1000] if text else f"port version exited {exit_code}"


def classify(binary: str | None, expected_binary: str, mismatch: str | None, check: registry.RegistryCheck, *,
             exit_code: int | None, stderr: str) -> tuple[Usability, str | None]:
    """Classify the usability and its detail: the checks run in order and the first that matches decides

    A busy registry (a finding that blocks everything) leaves a running `port` usable; a registry the
    user cannot read makes the instance CANNOT_RUN.

    @param binary           `<prefix>/bin/port`, or None when it is missing
    @param expected_binary  the path of the binary, for the detail of a missing one
    @param mismatch         the platform mismatch, or None
    @param check            the registry check
    @param exit_code        the exit status of `port version`; None when it did not run
    @param stderr           the standard error of `port version`
    @returns                the usability and its detail; None for a usable instance
    """
    if binary is None:
        return Usability.MISSING_BINARY, f"{expected_binary} is missing"
    if mismatch:
        return Usability.PLATFORM_MISMATCH, mismatch
    if check.status == "missing":
        return Usability.NO_REGISTRY, f"{check.detail} does not exist"
    if READONLY_TEXT in stderr:
        return Usability.READONLY_REGISTRY, _error_text(stderr, exit_code)
    if exit_code != 0:
        return Usability.CANNOT_RUN, _error_text(stderr, exit_code)
    if check.status in ("ok", "busy"):
        return Usability.USABLE, None
    if check.status == "damaged":
        return Usability.DAMAGED_REGISTRY, check.detail
    return Usability.CANNOT_RUN, check.detail


def registry_busy(instance: Instance) -> bool:
    """Return whether the registry backup failed because another `port` holds the registry or keeps changing it

    @param instance  the MacPorts instance
    @returns         True when its `inventory_error` is a `RegistryBusy` one
    """
    error = instance.inventory_error
    return error is not None and error.startswith(registry.STATUS_LABELS["busy"] + ":")


# Locations ----------------------------------------------------------------------

def _executable(path: str) -> bool:
    """Return whether a path is a regular file the user may execute

    @param path  the path
    @returns     True for an executable file
    """
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _first_on_path(name: str, path_var: str) -> str | None:
    """Return the first executable of a name on a `PATH`; relative entries are skipped

    @param name      the program's name
    @param path_var  the `PATH` value
    @returns         the program's path; None when no entry holds it
    """
    for directory in path_var.split(":"):
        if not directory or not os.path.isabs(directory):
            continue
        candidate = os.path.join(directory, name)
        if _executable(candidate):
            return candidate
    return None


def _etc_paths_entries(path: str) -> list[str]:
    """Return the entries of `/etc/paths`, one per line

    @param path  the file
    @returns     the stripped lines that are not blank; empty when the file cannot be read
    """
    text = _read_text(path)
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def located_prefixes(environ: Mapping[str, str], default_prefix: str, etc_paths: str) -> list[str]:
    """Return the candidate prefixes in order

    They are the default prefix when it holds `etc/macports/macports.conf`, the prefix of the `port` first
    on PATH, and the `/etc/paths` entries ending in `/bin` whose parent holds `etc/macports/macports.conf`.

    @param environ         the environment, whose `PATH` is searched
    @param default_prefix  the default MacPorts prefix
    @param etc_paths       the `/etc/paths` file
    @returns               the prefixes, a prefix met twice listed twice
    """
    out: list[str] = []
    if os.path.isfile(os.path.join(default_prefix, CONF_REL)):
        out.append(default_prefix)
    port = _first_on_path("port", environ.get("PATH", ""))
    if port:
        out.append(os.path.dirname(os.path.dirname(os.path.realpath(port))))
    for entry in _etc_paths_entries(etc_paths):
        entry = os.path.normpath(entry)
        if entry.endswith("/bin") and os.path.isfile(os.path.join(os.path.dirname(entry), CONF_REL)):
            out.append(os.path.dirname(entry))
    return out


def _by_identity(paths: Sequence[str]) -> list[tuple[system.Identity, list[str]]]:
    """Group the paths by `(st_dev, st_ino)`, in the order of first appearance, with every spelling met

    @param paths  the paths; one that does not exist is left out
    @returns      the identity of each group and its spellings, each once
    """
    groups: list[tuple[system.Identity, list[str]]] = []
    for path in paths:
        ident = system.identity(path)
        if ident is None:
            continue
        for known, spellings in groups:
            if known == ident:
                if path not in spellings:
                    spellings.append(path)
                break
        else:
            groups.append((ident, [path]))
    return groups


class _Receipt:
    """The installer receipt's file list, read at most once per scan"""

    def __init__(self, runner) -> None:
        """Read nothing until a prefix needs the list

        @param runner  the runner that runs `pkgutil`
        """
        self.runner = runner
        self._files: frozenset[str] | None = None

    def base_files(self, prefix: str) -> BaseFiles:
        """Return base's files in a prefix, probing the receipt on the first call

        @param prefix  the MacPorts prefix
        @returns       the base files
        """
        if self._files is None:
            self._files = receipt_files(self.runner)
        return BaseFiles(prefix, self._files)


def _inventory_known(check: registry.RegistryCheck, prefix: str, portdbpath: str,
                     base: Callable[[], BaseFiles]) -> tuple[bool, str | None]:
    """Return whether the packages are known, and why not

    They are known when the backup passed, or when the registry is absent and the prefix shows no trace
    of a port.

    @param check       the registry check
    @param prefix      the MacPorts prefix
    @param portdbpath  the instance's `portdbpath`
    @param base        builds base's own files in the prefix, called only for an absent registry
    @returns           whether they are known, and the reason they are not; None when they are
    """
    if check.status == "ok":
        return True, None
    if check.status == "missing":
        if known_empty(prefix, portdbpath, base()):
            return True, None
        return False, f"{check.message}; images or files of ports remain"
    return False, check.message


def _instance(runner, environ: Mapping[str, str], host_arch: str, running: Platform, ident: system.Identity, *,
              spellings: list[str], is_default: bool, receipt: _Receipt) -> Instance:
    """Return the MacPorts instance at one located prefix, with its usability classified

    @param runner      the runner that probes `port version`
    @param environ     the environment, whose `HOME` holds the user's macports.conf
    @param host_arch   the host's architecture
    @param running     the running platform and its Darwin major
    @param ident       the prefix's `(st_dev, st_ino)`
    @param spellings   every spelling met for the prefix, the first naming it; gains the spelling of `macports.conf`
    @param is_default  whether this is the default prefix, the only one the receipt's version serves
    @param receipt     the installer receipt, read at most once per scan
    @returns           the instance
    """
    prefix = spellings[0]
    config = read_config(prefix, environ)
    portdbpath = config["portdbpath"]
    conf_prefix = config.get("prefix")
    if conf_prefix and conf_prefix not in spellings and system.identity(conf_prefix) == ident:
        spellings.append(conf_prefix)
    autoconf = read_autoconf(prefix)
    arch = instance_arch(runner, prefix, host_arch)
    version = autoconf.get("macports_version") or (package_version(runner) if is_default else None)
    expected = os.path.join(prefix, "bin", "port")
    binary = expected if os.path.isfile(expected) else None
    inst = Instance(manager=Manager.PORTS, prefix=prefix, identity=ident, spellings=tuple(spellings), binary=binary,
                    version=version, arch=arch, usability=Usability.CANNOT_RUN, usability_detail=None, drivable=False,
                    inventory_error=None, repository=None, cache_dir=None, portdbpath=portdbpath,
                    applications_dir=config["applications_dir"], features=features_for(version),
                    owned_roots=(prefix,), inventory_known=False)
    exit_code: int | None = None
    stderr = ""
    if binary is not None:
        result = runner.run(actions.version(inst, host_arch, f"0.ports.{slug(prefix)}.version"))
        exit_code, stderr = result.exit, result.stderr()
    check = registry.check_registry(portdbpath)
    mismatch = platform_mismatch(autoconf, running, arch, host_arch, stderr)
    inst.usability, inst.usability_detail = classify(binary, expected, mismatch, check, exit_code=exit_code,
                                                     stderr=stderr)
    inst.drivable = inst.usability is Usability.USABLE
    inst.inventory_known, inst.inventory_error = _inventory_known(
        check, prefix, portdbpath, lambda: receipt.base_files(prefix))
    return inst


def find_instances(runner, environ: Mapping[str, str], host_arch: str, *, platform: Platform | None = None,
                   default_prefix: str = DEFAULT_PREFIX, etc_paths: str = ETC_PATHS) -> list[Instance]:
    """Find every MacPorts instance on the host, drivable or not

    Located prefixes of one `(st_dev, st_ino)` are one instance, named by the first spelling met; the
    receipt's version serves only the default prefix, the one place the package installs.

    @param runner          the runner that runs the probes
    @param environ         the environment, whose `PATH` and `HOME` are read
    @param host_arch       the host's architecture
    @param platform        the running platform; None reads `uname`
    @param default_prefix  the default MacPorts prefix
    @param etc_paths       the `/etc/paths` file
    @returns               the instances, in the order the search meets their prefixes
    """
    running = platform or running_platform()
    default_ident = system.identity(default_prefix)
    receipt = _Receipt(runner)
    return [_instance(runner, environ, host_arch, running, ident, spellings=spellings,
                      is_default=ident == default_ident, receipt=receipt)
            for ident, spellings in _by_identity(located_prefixes(environ, default_prefix, etc_paths))]


def choose_target(instances: Sequence[Instance], host_arch: str, target_prefix: str | None, *,
                  default_prefix: str = DEFAULT_PREFIX) -> Instance | None:
    """Choose the MacPorts target of a `ports` plan

    With `--target-prefix`, the instance there (never an x86_64 one on an arm64 host, which the arm64-only
    Command Line Tools cannot build for); without it, the one at `/opt/local`, else the only instance.

    @param instances       the instances on the host, of both managers
    @param host_arch       the host's architecture
    @param target_prefix   the `--target-prefix` value, or None
    @param default_prefix  the default MacPorts prefix
    @returns               the target; None when no instance qualifies
    @throws TargetRefused  `--target-prefix` names an x86_64 instance on an arm64 host
    """
    ports = [i for i in instances if i.manager is Manager.PORTS]
    if target_prefix:
        ident = system.identity(target_prefix)
        match = next((i for i in ports if ident is not None and tuple(i.identity) == ident), None)
        if match is not None and host_arch == "arm64" and match.arch == "x86_64":
            raise TargetRefused(f"MacPorts at {match.prefix} is an Intel installation on an Apple Silicon Mac, and "
                                "ports cannot be built for it. Choose another --target-prefix")
        return match
    default = system.identity(default_prefix)
    for inst in ports:
        if default is not None and tuple(inst.identity) == default:
            return inst
    return ports[0] if len(ports) == 1 else None

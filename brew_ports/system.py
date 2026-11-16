"""macOS facts for the system checks, free space and path identity"""

from __future__ import annotations

import os
import platform
import pwd
import sys
from collections.abc import Iterable, Sequence
from typing import Any

from .model import Action, OnFailure

SW_VERS = "/usr/bin/sw_vers"
SYSCTL = "/usr/sbin/sysctl"
XCODE_SELECT = "/usr/bin/xcode-select"
XCODEBUILD = "/usr/bin/xcodebuild"
PKGUTIL = "/usr/sbin/pkgutil"
DSCL = "/usr/bin/dscl"
CHSH = "/usr/bin/chsh"
DU = "/usr/bin/du"
GIT = "/usr/bin/git"
LAUNCHCTL = "/bin/launchctl"
LIPO = "/usr/bin/lipo"
TAR = "/usr/bin/tar"
CLT_DIR = "/Library/Developer/CommandLineTools"
DATA_VOLUME = "/System/Volumes/Data"

Identity = tuple[int, int]


def probe(action_id: str, argv: Sequence[str], description: str) -> Action:
    """Build a read-only probe action, whose exit status is data

    @param action_id    the probe's action id
    @param argv         the command and its arguments
    @param description  what the probe reads
    @returns            the action, run without sudo
    """
    return Action(action_id=action_id, kind="command", argv=list(argv), sudo=False, description=description,
                  on_failure=OnFailure.PROBE, read_only=True)


def _probe_text(runner, action_id: str, argv: Sequence[str], description: str) -> str | None:
    """Run a probe and return what it printed

    @param runner       the command runner
    @param action_id    the probe's action id
    @param argv         the command and its arguments
    @param description  what the probe reads
    @returns            the stripped stdout, or None when the command fails or cannot start
    """
    try:
        result = runner.run(probe(action_id, argv, description))
    except OSError:
        return None
    if result.exit != 0:
        return None
    return result.stdout().strip()


def macos_version(runner) -> str | None:
    """Return the macOS version that `sw_vers` reports

    @param runner  the command runner
    @returns       the version, such as `15.7`, or None when `sw_vers` fails
    """
    return _probe_text(runner, "0.system.sw_vers", [SW_VERS, "-productVersion"], "macOS version")


def host_arch(runner) -> str:
    """Return arm64 when the hardware is Apple Silicon, even inside a Rosetta-translated shell

    `uname -m` and `platform.machine()` report x86_64 under Rosetta, so the host architecture comes from
    `hw.optional.arm64`.

    @param runner  the command runner
    @returns       `arm64` or `x86_64`
    """
    value = _probe_text(runner, "0.system.arm64", [SYSCTL, "-n", "hw.optional.arm64"], "Apple Silicon hardware")
    if value == "1":
        return "arm64"
    if value is None and platform.machine() == "arm64":
        return "arm64"
    return "x86_64"


def rosetta_translated(runner) -> bool:
    """Return whether the tool's own process runs under Rosetta

    @param runner  the command runner
    @returns       True when `sysctl.proc_translated` is 1
    """
    value = _probe_text(runner, "0.system.translated", [SYSCTL, "-n", "sysctl.proc_translated"],
                        "Rosetta translation of this process")
    return value == "1"


def clt_state(runner) -> dict[str, Any]:
    """Return the selected developer directory and the Command Line Tools receipt, for the toolchain checks

    @param runner  the command runner
    @returns       `developer_dir`, `clt_dir_exists` and `clt_receipt`, and `xcode_license_ok` when the
                   selected directory lies inside an app
    """
    selected = _probe_text(runner, "0.system.xcode_select", [XCODE_SELECT, "-p"], "selected developer directory")
    receipt = _probe_text(runner, "0.system.clt_receipt",
                          [PKGUTIL, "--pkg-info=com.apple.pkg.CLTools_Executables"], "Command Line Tools receipt")
    state: dict[str, Any] = {"developer_dir": selected, "clt_dir_exists": os.path.isdir(CLT_DIR),
                             "clt_receipt": receipt is not None}
    if selected and ".app/" in selected + "/":
        lic = runner.run(probe("0.system.xcode_license", [XCODEBUILD, "-license", "check"], "Xcode licence"))
        state["xcode_license_ok"] = lic.exit == 0
    return state


def free_bytes(path: str) -> int | None:
    """Return the free bytes, `f_frsize * f_bavail`, of the volume that holds a path

    @param path  a path on the volume
    @returns     the free bytes, or None when `statvfs` fails
    """
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    return st.f_frsize * st.f_bavail


ROOT_MESSAGE = "brew-ports refuses to run as root or under sudo (system-running-as-root); run it as yourself"


def running_as_root() -> bool:
    """Return whether the tool runs as root, or was started under sudo

    @returns  True when the effective uid is 0 or `SUDO_USER` is set
    """
    return os.geteuid() == 0 or "SUDO_USER" in os.environ


def login_name() -> str:
    """Return the user's login name

    @returns  the name of the real uid, else `USER` from the environment, else an empty string
    """
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return os.environ.get("USER", "")


def parse_dscl(text: str) -> dict[str, str]:
    """Parse the `Key: value` lines of a directory record that `dscl` printed

    A value may also sit on the indented lines after its `Key:` line.

    @param text  the output of `dscl . -read`
    @returns     each key mapped to its value, continuation lines joined with single spaces
    """
    out: dict[str, str] = {}
    key: str | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[:1].isspace() and key is not None:
            out[key] = (out[key] + " " + line.strip()).strip()
            continue
        name, sep, value = line.partition(":")
        if sep:
            key = name.strip()
            out[key] = value.strip()
    return out


def tool_path() -> str:
    """Return where brew-ports runs from: its zipapp, or the directory that holds the package

    @returns  the realpath of `brew-ports.pyz` or of the checkout
    """
    return os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def facts(runner) -> dict[str, Any]:
    """Return the system section of scan.json

    @param runner  the command runner
    @returns       the macOS version, the architecture, Python, the user and the toolchain facts
    """
    data: dict[str, Any] = {
        "macos": macos_version(runner),
        "host_arch": host_arch(runner),
        "translated": rosetta_translated(runner),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "python_path": os.path.realpath(sys.executable),
        "tool_path": tool_path(),
        "uid": os.getuid(),
        "user": login_name(),
        "home": os.path.expanduser("~"),
        "platform": sys.platform,
    }
    data.update(clt_state(runner))
    return data


# Path identity --------------------------------------------------------------

def identity(path: str) -> Identity | None:
    """Return the `(st_dev, st_ino)` of a directory or file, following symlinks

    @param path  the path
    @returns     the identity, or None when `stat` fails
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def same_path(a: str, b: str) -> bool:
    """Return whether two paths name the same existing file or directory

    @param a  a path
    @param b  another path
    @returns  True when both exist and have one identity
    """
    ia, ib = identity(a), identity(b)
    return ia is not None and ia == ib


def lies_under(path: str, prefix_identity: Identity, include_self: bool = True) -> bool:
    """Return whether a path is the directory with an identity, or lies below it

    The ancestors of its realpath are compared by identity, so a case variant or the `/System/Volumes/Data`
    spelling matches, and a string prefix never decides.

    @param path             the path, which need not exist
    @param prefix_identity  the identity of the prefix directory
    @param include_self     whether the prefix directory itself counts
    @returns                True when the realpath, or one of its ancestors, has the identity
    """
    current = os.path.realpath(path)
    first = True
    while True:
        if include_self or not first:
            ident = identity(current)
            if ident is not None and ident == prefix_identity:
                return True
        first = False
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def case_insensitive(path: str) -> bool:
    """Return whether the volume of an existing path ignores case

    The case-swapped spelling of the path has the same identity on a case-insensitive volume and none (or
    another one) on a case-sensitive one.

    @param path  an existing path that holds a letter
    @returns     True on a case-insensitive volume; False when the path is missing or has no letter to swap
    """
    swapped = path.swapcase()
    if swapped == path:
        return False
    ident = identity(path)
    return ident is not None and identity(swapped) == ident


def normalise_text_path(text: str, fold_case: bool) -> str:
    """Drop a leading `/System/Volumes/Data` and trailing slashes, and fold the case when asked

    @param text       a path as text, which need not exist
    @param fold_case  whether to fold the case, for a case-insensitive volume
    @returns          the normalised text; `/` for the root
    """
    if text == DATA_VOLUME or text.startswith(DATA_VOLUME + "/"):
        text = text[len(DATA_VOLUME):] or "/"
    text = text.rstrip("/") or "/"
    return text.casefold() if fold_case else text


def text_names_prefix(text_path: str, spellings: Iterable[str], fold_case: bool) -> bool:
    """Return whether a text path, which may name a gone prefix, lies under one of the prefix's spellings

    A gone prefix has no identity, so the texts are compared, each without a leading `/System/Volumes/Data`.

    @param text_path  a path as text, such as one an rc line names
    @param spellings  the prefix's spellings
    @param fold_case  whether to ignore case, for a case-insensitive volume
    @returns          True when the text is one of the spellings or lies below one
    """
    candidate = normalise_text_path(text_path, fold_case)
    for spelling in spellings:
        base = normalise_text_path(spelling, fold_case)
        if candidate == base or candidate.startswith(base.rstrip("/") + "/"):
            return True
    return False

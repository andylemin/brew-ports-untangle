"""The MacPorts base package procedure: download the signed installer for this macOS, stage, verify, install"""

from __future__ import annotations

import contextlib
import importlib.resources
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .. import __version__, system
from ..model import Action, Instance, OnFailure
from ..runner import PreflightError, RootFiles, curl_argv
from ..state import RunDir, slug
from . import actions, locate

RELEASE_URL = "https://api.github.com/repos/macports/macports-base/releases/latest"
LATEST_URL = "https://github.com/macports/macports-base/releases/latest"     # redirects to TAG_PREFIX + tag
TAG_PREFIX = "https://github.com/macports/macports-base/releases/tag/"
DOWNLOAD_PREFIX = "https://github.com/macports/macports-base/releases/download/"
INSTALLER = "/usr/sbin/installer"
STATUS_LINE = "Status: signed by a developer certificate issued by Apple for distribution"
NOTARY_LINE = "Notarization: trusted by the Apple notary service"
CHAIN_HEADER = "Certificate Chain:"
ASSET_RE = re.compile(r"^MacPorts-(\d[0-9A-Za-z.]*)-(\d+)-([A-Za-z]+)\.pkg$")
CHAIN_RE = re.compile(r"^\d+\.\s+(.*\S)\s*$")
TAG_RE = re.compile(r"^v\d[0-9A-Za-z.]*$")
REFUSED_RE = re.compile(r"returned error: (403|429)\b")     # the API's rate limit, as curl --fail reports it
# The macOS name in each major's package of a macports-base release: MacPorts-<version>-<major>-<name>.pkg.
PACKAGE_NAMES = {11: "BigSur", 12: "Monterey", 13: "Ventura", 14: "Sonoma", 15: "Sequoia", 26: "Tahoe",
                 27: "GoldenGate"}
# The shell files the installer's postflight appends its PATH lines to, as root, creating a missing one.
SHELL_FILES = (".bash_profile", ".bash_login", ".profile", ".zprofile", ".tcshrc", ".cshrc")


class BootstrapError(PreflightError):
    """The base package cannot be had: no release, no package for this macOS (exit 3)"""


class SignatureMismatch(BootstrapError):
    """The staged package is not signed by a pinned signer (exit 3, the chain printed)"""


@dataclass
class Asset:
    """One base package of a `macports-base` release, the one for the running macOS major"""

    name: str          # MacPorts-2.12.7-26-Tahoe.pkg
    url: str
    version: str       # 2.12.7
    major: int         # 26


def _id(runner, step: str) -> str:
    """Return an action id that starts with the runner's phase, 0 outside a phase

    The id is `<phase>.<step>`.

    @param runner  the runner, whose current phase starts the id
    @param step    the rest of the id, such as `base.download`
    @returns       the action id
    """
    return f"{0 if runner.phase is None else runner.phase}.{step}"


def _download(action_id: str, url: str, output: str, description: str, write_out: str | None = None) -> Action:
    """Build the curl download of `url` into `output`, a probe whose exit status the caller reads

    @param action_id    the action's `<phase>.<step>` id
    @param url          the HTTPS URL to fetch
    @param output       the file curl writes
    @param description  the text shown for the action
    @param write_out    the `--write-out` format curl prints on stdout after the transfer; None for none
    @returns            the action
    """
    # Not read_only: a read-only action times out after 120 s, and the package is large.
    argv = curl_argv(url, output, user_agent="brew-ports/" + __version__)
    if write_out:
        argv[-1:-1] = ["--write-out", write_out]
    return Action(action_id=action_id, kind="command", argv=argv, sudo=False, description=description,
                  on_failure=OnFailure.PROBE)


def macos_major(version: str | None) -> int:
    """Return the major of a `sw_vers -productVersion` string: 15 for 15.7.1

    @param version          the macOS version, or None when it is unknown
    @returns                the major version
    @throws BootstrapError  the version does not start with a number
    """
    try:
        return int((version or "").split(".")[0])
    except ValueError:
        raise BootstrapError(f"cannot read the macOS version ({version!r})") from None


def _latest_tag(runner, downloads: str, refusal: str) -> str:
    """Return the tag of the latest `macports-base` release, read from the redirect of its `releases/latest` page

    @param runner     the runner that runs curl
    @param downloads  the run's downloads directory, which receives `macports-base-latest.html`
    @param refusal    the HTTP status the GitHub API refused the release read with, for the error
    @returns          the tag, such as `v2.12.7`
    """
    path = os.path.join(downloads, "macports-base-latest.html")
    result = runner.run(_download(_id(runner, "base.latest"), LATEST_URL, path,
                                  "read the tag of the latest MacPorts base release", write_out="%{url_effective}"))
    landed = result.stdout().strip()
    tag = landed[len(TAG_PREFIX):] if result.exit == 0 and landed.startswith(TAG_PREFIX) else ""
    if not TAG_RE.match(tag):
        raise BootstrapError(f"{RELEASE_URL} answered HTTP {refusal}, and {LATEST_URL} named no release tag "
                             f"(curl exit {result.exit}, at {landed or 'no URL'}): {result.stderr().strip()}")
    return tag


def _release_of_tag(tag: str, major: int, refusal: str) -> dict[str, Any]:
    """Return a release description in the GitHub API's shape: the tag and its package for the running macOS major

    The package is named as every `macports-base` release names them, with the major's name in `PACKAGE_NAMES`.

    @param tag      the release's tag, such as `v2.12.7`
    @param major    the running macOS major
    @param refusal  the HTTP status the GitHub API refused the release read with, for the error
    @returns        the description, with `tag_name` and one asset
    """
    name = PACKAGE_NAMES.get(major)
    if name is None:
        raise BootstrapError(f"{RELEASE_URL} answered HTTP {refusal}, and the name of the MacPorts {tag} package for "
                             f"macOS {major} is not known without it: try again later")
    asset = f"MacPorts-{tag[1:]}-{major}-{name}.pkg"
    return {"tag_name": tag, "assets": [{"name": asset, "browser_download_url": f"{DOWNLOAD_PREFIX}{tag}/{asset}"}]}


def fetch_release(runner, downloads: str, major: int) -> dict[str, Any]:
    """Fetch the latest `macports-base` release from the GitHub API, through curl

    When the API refuses with HTTP 403 or 429, its rate limit for an address many hosts share, the release is the tag
    `releases/latest` redirects to, with the package named as the releases name them.

    @param runner     the runner that runs curl
    @param downloads  the run's downloads directory, which receives `macports-base-release.json`
    @param major      the running macOS major, whose package a release read from the redirect names
    @returns          the release description, a JSON object
    """
    path = os.path.join(downloads, "macports-base-release.json")
    result = runner.run(_download(_id(runner, "base.release"), RELEASE_URL, path,
                                  "read the latest MacPorts base release"))
    if result.exit != 0:
        refused = REFUSED_RE.search(result.stderr())
        if refused:
            return _release_of_tag(_latest_tag(runner, downloads, refused.group(1)), major, refused.group(1))
        raise BootstrapError(f"could not read {RELEASE_URL} (curl exit {result.exit}): {result.stderr().strip()}")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise BootstrapError(f"the MacPorts release description is unreadable: {exc}") from None
    if not isinstance(data, dict):
        raise BootstrapError("the MacPorts release description is not an object")
    return data


def choose_asset(release: Mapping[str, Any], major: int) -> Asset:
    """Return the asset `MacPorts-<version>-<major>-<Name>.pkg` for the running macOS major

    @param release  the release description from the GitHub API
    @param major    the running macOS major
    @returns        the asset, whose URL lies under the release download prefix
    """
    for asset in release.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        name, url = asset.get("name") or "", asset.get("browser_download_url")
        match = ASSET_RE.match(name)
        if match and int(match.group(2)) == major and isinstance(url, str) and url.startswith(DOWNLOAD_PREFIX):
            return Asset(name=name, url=url, version=match.group(1), major=major)
    tag = release.get("tag_name") or "unknown"
    raise BootstrapError(f"the latest MacPorts base release ({tag}) has no package for macOS {major}")


def trusted_signers() -> list[str]:
    """Return the pinned signers of `data/trusted-signers.json`

    @returns  the signer names, as the first line of a certificate chain prints them
    """
    text = importlib.resources.files("brew_ports.data").joinpath("trusted-signers.json").read_text(encoding="utf-8")
    return [s for s in json.loads(text) if isinstance(s, str)]


def _chain(lines: Sequence[str]) -> list[str]:
    """Return the numbered certificate lines after the `Certificate Chain:` header

    @param lines  the stripped lines of `pkgutil --check-signature` output
    @returns      the lines that match `CHAIN_RE`; empty without the header
    """
    if CHAIN_HEADER not in lines:
        return []
    return [line for line in lines[lines.index(CHAIN_HEADER) + 1:] if CHAIN_RE.match(line)]


def check_signature(text: str, trusted: Sequence[str]) -> str:
    """Return the pinned signer that `pkgutil --check-signature` output names, or raise `SignatureMismatch`

    The output must hold the Developer ID distribution `Status:` line, the `Notarization:` line and a
    first certificate-chain line whose text after its `N. ` ordinal is a pinned signer.

    @param text     the output of `pkgutil --check-signature`
    @param trusted  the pinned signers
    @returns        the signer
    """
    lines = [line.strip() for line in text.splitlines()]
    chain = _chain(lines)
    first = CHAIN_RE.match(chain[0]) if chain else None
    if first is not None and STATUS_LINE in lines and NOTARY_LINE in lines and first.group(1) in trusted:
        return first.group(1)
    shown = "\n".join("  " + line for line in (chain or [l for l in lines if l])) or "  (no output)"
    raise SignatureMismatch(f"the MacPorts package is not signed by a pinned signer ({', '.join(trusted)}); "
                            f"pkgutil printed:\n{shown}")


def install_package(runner, files: RootFiles, pkg: str) -> str:
    """Stage, verify and install one base package; the staging directory goes in every case

    Root reads only the staged copy, which `files.stage` puts in a root-owned directory.

    @param runner  the runner that runs `pkgutil` and `installer` under `sudo`
    @param files   the root staging directory
    @param pkg     the downloaded package
    @returns       the pinned signer of the package
    """
    try:
        staged = files.stage(pkg, os.path.basename(pkg))
        result = runner.run(Action(action_id=_id(runner, "base.signature"), kind="command",
                                   argv=[system.PKGUTIL, "--check-signature", staged], sudo=True,
                                   description="check the signature of the staged MacPorts package",
                                   on_failure=OnFailure.PROBE, read_only=True))
        signer = check_signature(result.stdout(), trusted_signers())
        runner.run(Action(action_id=_id(runner, "base.installer"), kind="command",
                          argv=[INSTALLER, "-pkg", staged, "-target", "/"], sudo=True,
                          description=f"install MacPorts base from {os.path.basename(pkg)}"))
    finally:
        files.remove_staging()
    return signer


def base_package_procedure(runner, run_dir: RunDir, macos_version: str | None = None,
                           files: RootFiles | None = None) -> Asset:
    """Download, stage, verify and install the latest base package for this macOS

    Confirmation is the caller's. The postflight writes the shell block and exits 0 even when its
    `port -v selfupdate` fails, so a `sudo port -N sync` follows (`bootstrap` and the manager repairs).

    @param runner         the runner that carries out every step
    @param run_dir        the run directory, whose `downloads` receives the package
    @param macos_version  the macOS version; None asks `sw_vers`
    @param files          the root staging directory; None makes one for the run
    @returns              the asset installed
    """
    major = macos_major(macos_version or system.macos_version(runner))
    downloads = run_dir.ensure("downloads")
    asset = choose_asset(fetch_release(runner, downloads, major), major)
    pkg = os.path.join(downloads, asset.name)
    result = runner.run(_download(_id(runner, "base.download"), asset.url, pkg, f"download {asset.name}"))
    if result.exit != 0:
        raise BootstrapError(f"could not download {asset.url} (curl exit {result.exit})")
    install_package(runner, files or RootFiles(runner, run_dir.run_id), pkg)
    return asset


def _shell_file_owners(home: str) -> dict[str, int | None]:
    """Return the owner of each of the installer's `SHELL_FILES` in a home, to compare with after the install

    @param home  the user's home directory
    @returns     the owner's uid by path; None for a file that does not exist
    """
    owners: dict[str, int | None] = {}
    for name in SHELL_FILES:
        path = os.path.join(home, name)
        try:
            owners[path] = os.lstat(path).st_uid
        except OSError:
            owners[path] = None
    return owners


def _rewrite_as_user(path: str, st: os.stat_result) -> None:
    """Put over a file a copy with its bytes and mode, written by this process through a temporary file beside it

    The read refuses a symlink and a file other than the one `st` describes; `os.replace` swaps only the directory
    entry, so no other file is reached.

    @param path      the file, in a directory this process can write
    @param st        the file's `lstat` when it was judged
    @throws OSError  the file is not that one any more, or it cannot be read, or the copy cannot be written or moved
    """
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as fh:
        opened = os.fstat(fh.fileno())
        if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            raise OSError(f"{path} changed while it was read")
        data = fh.read()
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
            os.fchmod(out.fileno(), stat.S_IMODE(st.st_mode))
        os.replace(tmp, path)
    except BaseException:   # interrupts too: the copy goes, and the original stays
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _give_back(console, before: Mapping[str, int | None], user: str) -> None:
    """Give back to the user each shell file the installer created or replaced and left to root, without sudo

    A file counts when it was missing or the user's before the install and is root's after it. The user owns the home,
    so a regular file with one link is replaced by the user's copy of it (`_rewrite_as_user`); any other is left alone,
    and the output says so.

    @param console  where each file given back or left alone is reported
    @param before   the owners `_shell_file_owners` recorded before the install
    @param user     the user's name, for the output
    """
    for path, owner in before.items():
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if st.st_uid != 0 or owner not in (None, os.getuid()):
            continue
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            console.out(f"left {path} alone: the MacPorts installer left it owned by root, and it is not a plain file "
                        f"with one link; check it and give it back to {user} by hand")
            continue
        try:
            _rewrite_as_user(path, st)
        except OSError as exc:
            console.out(f"could not give {path} back to {user}: {exc}")
            continue
        console.out(f"gave {path} back to {user}: the MacPorts installer left it owned by root")


def _new_instance(instances: Sequence[Instance], default_prefix: str) -> Instance:
    """Return the instance at the default prefix, matched by the prefix's identity

    @param instances       the MacPorts instances located after the install
    @param default_prefix  the prefix the base package installs into
    @returns               the instance there
    """
    ident = system.identity(default_prefix)
    for inst in instances:
        if ident is not None and tuple(inst.identity) == ident:
            return inst
    raise BootstrapError(f"MacPorts base was installed, but no instance was found at {default_prefix}")


def bootstrap(runner, run_dir: RunDir, environ: Mapping[str, str], host_arch: str, *,
              macos_version: str | None = None, files: RootFiles | None = None,
              default_prefix: str = locate.DEFAULT_PREFIX) -> Instance:
    """Run `bootstrap-ports`: the base package procedure and `sudo port -N sync`

    The installer's postflight runs as root, so the shell files it wrote in the user's home go back to the user.

    @param runner           the runner that carries out every step
    @param run_dir          the run directory, whose `downloads` receives the package
    @param environ          the environment the instances are located with, whose `HOME` holds the shell files
    @param host_arch        the host's architecture
    @param macos_version    the macOS version; None asks `sw_vers`
    @param files            the root staging directory; None makes one for the run
    @param default_prefix   the prefix the base package installs into
    @returns                the instance at that prefix, located again after the sync
    @throws BootstrapError  the package cannot be had, is not signed by a pinned signer, or leaves no instance
    @throws ActionFailed    the installer or `sudo port -N sync` failed
    """
    home = environ.get("HOME")
    before = _shell_file_owners(home) if home else {}
    try:
        base_package_procedure(runner, run_dir, macos_version, files)
    finally:
        _give_back(runner.console, before, environ.get("USER") or str(os.getuid()))
    instance = _new_instance(locate.find_instances(runner, environ, host_arch, default_prefix=default_prefix),
                             default_prefix)
    runner.run(actions.sync(instance, host_arch, _id(runner, f"ports.{slug(instance.prefix)}.sync")))
    return _new_instance(locate.find_instances(runner, environ, host_arch, default_prefix=default_prefix),
                         default_prefix)


def describe(major: int) -> list[str]:
    """Return the steps of the procedure, for the confirmation and `--dry-run`

    @param major  the running macOS major
    @returns      one line per step
    """
    return [
        f"read {RELEASE_URL} (on HTTP 403 or 429, the release tag {LATEST_URL} redirects to)",
        f"download MacPorts-<version>-{major}-<name>.pkg into <run>/downloads/",
        "copy it into a root-owned staging directory (sudo install -m 0644)",
        "check its signature on the staged copy (sudo pkgutil --check-signature; "
        f"pinned: {', '.join(trusted_signers())})",
        "install it (sudo installer -pkg <staged copy> -target /), then remove the staging directory",
        "give back to you the shell files in your home that the installer wrote and left owned by root: each becomes "
        "your copy, with the same content and mode",
        "sync the ports tree (sudo port -N sync) and locate the new instance",
    ]

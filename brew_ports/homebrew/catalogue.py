"""The offline Homebrew catalogue and the rules that read cask artifacts

The catalogue is read from `<cache_dir>/api/` or the tap checkouts, and never downloaded.
"""

from __future__ import annotations

import datetime
import glob
import json
import os
import re
import shlex
import stat
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .. import model
from . import locate

LAUNCH_DAEMONS = "/Library/LaunchDaemons"
LAUNCH_AGENTS = "/Library/LaunchAgents"

# cask/config.rb DEFAULT_DIRS of Homebrew 7.
DEFAULT_CASK_DIRS = {
    "appdir": "/Applications",
    "appimagedir": "~/Applications",
    "keyboard_layoutdir": "/Library/Keyboard Layouts",
    "colorpickerdir": "~/Library/ColorPickers",
    "prefpanedir": "~/Library/PreferencePanes",
    "qlplugindir": "~/Library/QuickLook",
    "mdimporterdir": "~/Library/Spotlight",
    "dictionarydir": "~/Library/Dictionaries",
    "fontdir": "~/Library/Fonts",
    "servicedir": "~/Library/Services",
    "input_methoddir": "~/Library/Input Methods",
    "internet_plugindir": "~/Library/Internet Plug-Ins",
    "audio_unit_plugindir": "~/Library/Audio/Plug-Ins/Components",
    "vst_plugindir": "~/Library/Audio/Plug-Ins/VST",
    "vst3_plugindir": "~/Library/Audio/Plug-Ins/VST3",
    "screen_saverdir": "~/Library/Screen Savers",
}
# Moved artifacts and the configuration directory they land in.
KIND_DIRS = {
    "app": "appdir", "suite": "appdir", "app_image": "appimagedir", "keyboard_layout": "keyboard_layoutdir",
    "colorpicker": "colorpickerdir", "prefpane": "prefpanedir", "qlplugin": "qlplugindir",
    "mdimporter": "mdimporterdir", "dictionary": "dictionarydir", "font": "fontdir", "service": "servicedir",
    "input_method": "input_methoddir", "internet_plugin": "internet_plugindir",
    "audio_unit_plugin": "audio_unit_plugindir", "vst_plugin": "vst_plugindir", "vst3_plugin": "vst3_plugindir",
    "screen_saver": "screen_saverdir",
}
# Symlinked artifacts and their directory under the prefix.
PREFIX_DIRS = {
    "binary": "bin", "command_wrapper": "bin", "manpage": os.path.join("share", "man"),
    "bash_completion": os.path.join("etc", "bash_completion.d"),
    "zsh_completion": os.path.join("share", "zsh", "site-functions"),
    "fish_completion": os.path.join("share", "fish", "vendor_completions.d"),
    "pwsh_completion": os.path.join("share", "pwsh", "completions"),
}
INSTALL_FLIGHTS = frozenset(("preflight", "postflight", "preflight_steps", "postflight_steps"))
UNINSTALL_FLIGHTS = frozenset(("uninstall_preflight", "uninstall_postflight", "uninstall_preflight_steps",
                               "uninstall_postflight_steps"))
DIRECTIVE_KINDS = frozenset(("uninstall", "zap", "installer")) | INSTALL_FLIGHTS | UNINSTALL_FLIGHTS
SUDO_UNINSTALL_DIRECTIVES = ("pkgutil", "kext", "delete", "rmdir")
_PYTHON = re.compile(r"^python@3\.\d+$")


# Small helpers ----------------------------------------------------------------

def plain_keys(value: Any) -> Any:
    """Drop the leading colon that the API's cask DSL keys keep (`:pkg`, `:target`), at every depth

    @param value  a decoded JSON value
    @returns      a copy whose dict keys have no leading colon; a scalar unchanged
    """
    if isinstance(value, dict):
        return {plain_symbol(k): plain_keys(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain_keys(v) for v in value]
    return value


def plain_symbol(value: Any) -> Any:
    """Drop the leading colon of a DSL symbol: `:unmaintained` -> `unmaintained`

    @param value  a decoded JSON value
    @returns      a string without its leading colon; any other value unchanged
    """
    return value[1:] if isinstance(value, str) and value.startswith(":") else value


def _as_list(value: Any) -> list[Any]:
    """Return a JSON value as a list

    @param value  a decoded JSON value, or None
    @returns      empty for None, the items of a list or tuple, else a one-item list
    """
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def version_key(version: str) -> tuple[Any, ...]:
    """Return a sort key for Homebrew versions, where `1.8.2_1` is version `1.8.2`, revision 1

    Numbers compare numerically and above words: enough to pick the newest keg or cask version.

    @param version  a keg or cask version, with an optional `_<revision>`
    @returns        the key: the version's number and word tokens, then the revision
    """
    base, sep, revision = version.rpartition("_")
    if sep and revision.isdigit():
        rev = int(revision)
    else:
        base, rev = version, 0
    tokens = tuple((1, int(t), "") if t.isdigit() else (0, 0, t.lower()) for t in re.findall(r"\d+|[A-Za-z]+", base))
    return (tokens, rev)


def normalise_url(url: str | None) -> str | None:
    """Normalise a homepage for matching

    The result has `https`, a lower-cased host without `www.`, no trailing slash and no fragment.

    @param url  a homepage URL, or None
    @returns    the normalised URL, or None for an empty one
    """
    if not url:
        return None
    url = url.strip().split("#", 1)[0]
    match = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://([^/]*)(.*)$", url)
    if not match:
        return url.rstrip("/") or None
    host, rest = match.group(1).lower(), match.group(2)
    if host.startswith("www."):
        host = host[4:]
    return ("https://" + host + rest).rstrip("/")


def _parse_date(args: Any) -> datetime.date | None:
    """Return the date of a `deprecate_args` or `disable_args` entry

    @param args  the entry's arguments, whose `date` or `:date` holds an ISO date
    @returns     the date, or None when there is none or it does not parse
    """
    if not isinstance(args, dict):
        return None
    value = args.get(":date", args.get("date"))
    try:
        return datetime.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def lifecycle(entry: Mapping[str, Any], today: datetime.date, kind: str = "formula") -> tuple[bool, bool]:
    """Return `(deprecated, disabled)` of a formula or cask entry on `today`, as Homebrew evaluates them

    A date equal to today has passed; a future disable date deprecates a cask always (`cask/dsl.rb`), a formula
    only without `deprecate_args`.

    @param entry  the formula or cask entry of the API payload
    @param today  the date the entry is judged on
    @param kind   `formula` or `cask`
    @returns      whether the entry is deprecated, and whether it is disabled
    """
    deprecate, disable = entry.get("deprecate_args"), entry.get("disable_args")
    deprecate_date = _parse_date(deprecate) if deprecate else None
    disable_date = _parse_date(disable) if disable else None
    disable_ahead = disable_date is not None and disable_date > today
    deprecated = ((deprecate_date is not None and deprecate_date <= today)
                  or (disable_ahead and (kind == "cask" or not deprecate)))
    disabled = disable_date is not None and disable_date <= today
    return deprecated, disabled


# Cask artifacts -----------------------------------------------------------

@dataclass
class Artifact:
    """One cask artifact: its kind and arguments, whatever shape Homebrew writes it in"""
    kind: str                                              # "app", "pkg", "uninstall", "postflight_steps", ...
    positional: list[Any] = field(default_factory=list)    # sources and other positional arguments
    directives: dict[str, Any] = field(default_factory=dict)  # uninstall, zap, installer and flight contents
    options: dict[str, Any] = field(default_factory=dict)  # keyword options, `target` among them
    target: str | None = None                           # the resolved target the installed JSON reports


def _artifact(kind: str, args: Sequence[Any], target: str | None) -> Artifact:
    """Build an artifact from its arguments, a dict giving directives or options by the artifact kind

    @param kind    the artifact kind, such as `app` or `uninstall`
    @param args    the arguments after the kind: values, lists of values and dicts, their keys without colons
    @param target  the resolved target the installed JSON reports, or None
    @returns       the artifact
    """
    art = Artifact(kind=kind, target=target)
    for arg in args:
        if isinstance(arg, list):
            art.positional.extend(arg)
        elif isinstance(arg, dict):
            (art.directives if kind in DIRECTIVE_KINDS else art.options).update(arg)
        elif arg is not None:
            art.positional.append(arg)
    return art


def normalise_artifacts(items: Iterable[Any] | None) -> list[Artifact]:
    """Return the `Artifact`s of any shape Homebrew writes them in

    The API writes `[":kind", args..., {":option": ...}]` lists; `brew info` and receipts write
    `{"kind": [args...], "target": ...}` dicts, a flight block as `{"postflight, uninstall_postflight": null}`.

    @param items  the API's `raw_artifacts`, the `artifacts` of `brew info`, or a receipt's `uninstall_artifacts`
    @returns      the artifacts, in their order
    """
    out: list[Artifact] = []
    for item in items or []:
        if isinstance(item, list) and item and isinstance(item[0], str):
            out.append(_artifact(item[0].lstrip(":"), plain_keys(item[1:]), None))
        elif isinstance(item, dict):
            item = plain_keys(item)
            target = item.get("target") if isinstance(item.get("target"), str) else None
            for key, value in item.items():
                if key == "target":
                    continue
                for kind in re.split(r",\s*", str(key)):
                    if kind:
                        out.append(_artifact(kind.strip(), _as_list(value), target))
    return out


def expand_path(path: str, prefix: str, dirs: Mapping[str, str], home: str) -> str:
    """Expand `$HOMEBREW_PREFIX`, `$APPDIR` and a leading `~` in an artifact path

    @param path    an artifact path or a `--<kind>dir` value
    @param prefix  the Homebrew prefix
    @param dirs    the artifact directories, for `appdir`; `/Applications` when it has none
    @param home    the user's home directory
    @returns       the expanded path
    """
    path = path.replace("$HOMEBREW_PREFIX", prefix).replace("$APPDIR", dirs.get("appdir", "/Applications"))
    if path == "~" or path.startswith("~/"):
        path = home + path[1:]
    return path


def cask_dirs(prefix: str, environ: Mapping[str, str], lines: Sequence[locate.EnvLine] = (),
              home: str | None = None) -> dict[str, str]:
    """Return the artifact directories: Homebrew's defaults, overridden by the `--<kind>dir` options `brew` sees

    The options come from `HOMEBREW_CASK_OPTS`, in the environment or a `brew.env` line, read as Homebrew's
    `Cask::Config` reads them: only a word that holds `=` counts, its leading `--` dropped and its hyphens read
    as underscores.

    @param prefix   the Homebrew prefix
    @param environ  the environment `brew` starts with
    @param lines    the `brew.env` lines `bin/brew` exports over it
    @param home     the user's home directory; None takes `HOME` from `environ`
    @returns        the directories by configuration key, such as `appdir`
    """
    home = home or environ.get("HOME") or os.path.expanduser("~")
    dirs = {key: expand_path(value, prefix, {}, home) for key, value in DEFAULT_CASK_DIRS.items()}
    opts = locate.effective("HOMEBREW_CASK_OPTS", environ, lines) or ""
    try:
        words = shlex.split(opts)
    except ValueError:
        words = opts.split()
    for word in words:
        name, sep, value = word.partition("=")
        key = name.removeprefix("--").replace("-", "_")
        if sep and value and key in dirs:
            dirs[key] = expand_path(value, prefix, dirs, home)
    return dirs


def dirs_from_config(config: Any, fallback: Mapping[str, str]) -> dict[str, str]:
    """Return `fallback` overridden by a cask's `.metadata/config.json`: explicit over environment over default

    @param config    the decoded `config.json`; anything but a dict for none
    @param fallback  the artifact directories to start from
    @returns         the directories by configuration key
    """
    dirs = dict(fallback)
    if isinstance(config, dict):
        for section in ("default", "env", "explicit"):
            part = config.get(section)
            if isinstance(part, dict):
                dirs.update({k: v for k, v in part.items() if isinstance(v, str) and k.endswith("dir")})
    return dirs


def artifact_targets(art: Artifact, dirs: Mapping[str, str], prefix: str, home: str) -> list[str]:
    """Return where an artifact is moved or linked

    The installed JSON's `target`, an explicit `target:` option, or the source's basename in the kind's directory.

    @param art     the artifact
    @param dirs    the artifact directories by configuration key
    @param prefix  the Homebrew prefix, for the kinds linked under it
    @param home    the user's home directory
    @returns       the target as a one-item list; empty when there is none to tell
    """
    if art.target:
        return [art.target]
    if art.kind in KIND_DIRS:
        base = dirs.get(KIND_DIRS[art.kind])
    elif art.kind == "manpage":
        source = str(art.positional[0]) if art.positional else ""
        section = re.search(r"\.([1-8]|n|l)(?:\.gz)?$", source)
        base = os.path.join(prefix, PREFIX_DIRS["manpage"], "man" + (section.group(1) if section else "1"))
    elif art.kind in PREFIX_DIRS:
        base = os.path.join(prefix, PREFIX_DIRS[art.kind])
    elif art.kind == "artifact":
        base = None
    else:
        return []
    explicit = art.options.get("target")
    if isinstance(explicit, str) and explicit:
        path = expand_path(explicit, prefix, dirs, home)
        if os.path.isabs(path):
            return [path]
        return [os.path.join(base, path)] if base else []
    sources = [s for s in art.positional if isinstance(s, str) and s]
    if not sources or not base:
        return []
    return [os.path.join(base, os.path.basename(expand_path(sources[0], prefix, dirs, home).rstrip("/")))]


def tree_owned_by(path: str, uid: int) -> bool:
    """Return whether `path` and every entry below it belong to `uid`, symlinks not followed

    An entry that cannot be read counts as not owned.

    @param path  the path to test
    @param uid   the owner to look for
    @returns     True when every entry belongs to `uid`, or when `path` does not exist
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if st.st_uid != uid:
        return False
    if not stat.S_ISDIR(st.st_mode):
        return True
    errors: list[OSError] = []
    for dirpath, dirnames, filenames in os.walk(path, onerror=errors.append):
        for name in dirnames + filenames:
            try:
                if os.lstat(os.path.join(dirpath, name)).st_uid != uid:
                    return False
            except FileNotFoundError:
                continue
            except OSError:
                return False
    return not errors


def _sudo(value: Any) -> bool:
    """Return whether a script directive, or any in a list of them, sets `sudo: true`

    @param value  a `script` or `early_script` directive: a dict, a list of them, or a path
    @returns      True when one of them runs under sudo
    """
    if isinstance(value, list):
        return any(_sudo(v) for v in value)
    return isinstance(value, dict) and value.get("sudo") is True


@dataclass
class PrivilegeContext:
    """What `privileged_flags` needs to know about the instance and the user"""
    prefix: str
    dirs: dict[str, str]
    home: str
    uid: int
    system_loaded: Callable[[str], bool] = lambda label: False  # `launchctl print system/<label>` succeeded


def system_job(label: str, ctx: PrivilegeContext) -> bool:
    """Return whether only Homebrew's root pass removes the `launchctl` label

    It has a plist in `/Library/LaunchDaemons` or `/Library/LaunchAgents`, or a job loaded in the `system` domain.

    @param label  a `launchctl` label of an `uninstall` directive, perhaps with a `*` wildcard
    @param ctx    the privilege context, for the `system` domain probe
    @returns      True when removing the job needs root
    """
    dirs = (LAUNCH_DAEMONS, LAUNCH_AGENTS)
    if "*" in label:
        return any(glob.glob(os.path.join(d, label + ".plist")) for d in dirs)
    return any(os.path.lexists(os.path.join(d, label + ".plist")) for d in dirs) or ctx.system_loaded(label)


def _sudo_step_at_uninstall(art: Artifact) -> bool:
    """Return whether a `preflight_steps` or `postflight_steps` block may call sudo at uninstall

    Homebrew runs `uninstall: true` steps again at uninstall, where `sudo: true` or `if_needed` escalates; a block
    whose steps the JSON hides counts as escalating.

    @param art  a `preflight_steps` or `postflight_steps` artifact
    @returns    True when a step may escalate at uninstall
    """
    steps = art.directives.get("steps")
    if not isinstance(steps, list):
        return True
    for step in steps:
        if isinstance(step, dict) and step.get("uninstall") and step.get("sudo") not in (None, False, "false"):
            return True
    return False


def privileged_flags(artifacts: Sequence[Artifact], ctx: PrivilegeContext) -> tuple[bool, bool]:
    """Return `(privileged_install, privileged_uninstall)` of a cask with these artifacts

    @param artifacts  the cask's artifacts
    @param ctx        the instance and user the cask installs for
    @returns          whether `brew` may call sudo to install the cask, and whether to uninstall it
    """
    install = uninstall = False
    for art in artifacts:
        kind = art.kind
        if kind in ("pkg", "keyboard_layout") or kind in INSTALL_FLIGHTS:
            install = True
        if kind == "installer" and _sudo(art.directives.get("script")):
            install = True
        if kind == "keyboard_layout" or kind in UNINSTALL_FLIGHTS:
            uninstall = True
        if kind in ("preflight_steps", "postflight_steps") and _sudo_step_at_uninstall(art):
            uninstall = True
        if kind == "uninstall":
            d = art.directives
            if (any(d.get(name) for name in SUDO_UNINSTALL_DIRECTIVES) or _sudo(d.get("script"))
                    or _sudo(d.get("early_script"))):
                uninstall = True
            if not uninstall and any(system_job(str(label), ctx) for label in _as_list(d.get("launchctl"))):
                uninstall = True
        for target in artifact_targets(art, ctx.dirs, ctx.prefix, ctx.home):
            if not os.access(os.path.dirname(target), os.W_OK):
                install = uninstall = True
            if not uninstall and os.path.lexists(target) and not tree_owned_by(target, ctx.uid):
                uninstall = True
    return install, uninstall


@dataclass
class CaskInfo:
    """A catalogue cask: its metadata, artifacts, dependencies and both privileged flags"""
    token: str
    version: str | None
    homepage: str | None
    desc: str | None
    tap: str | None
    artifacts: list[Artifact]
    depends_formula: list[str]
    depends_cask: list[str]
    auto_updates: bool
    privileged_install: bool
    privileged_uninstall: bool


def depends_lists(depends_on: Any) -> tuple[list[str], list[str]]:
    """Return the formula names and cask tokens of a `depends_on` (JSON) or `depends_on_args` (API)

    @param depends_on  the dependency dict, its keys with or without colons; anything else for none
    @returns           the formula names and the cask tokens, each without its tap
    """
    data = plain_keys(depends_on) if isinstance(depends_on, dict) else {}
    formulae = [str(n).rsplit("/", 1)[-1] for n in _as_list(data.get("formula"))]
    casks = [str(n).rsplit("/", 1)[-1] for n in _as_list(data.get("cask"))]
    return formulae, casks


# The catalogue ----------------------------------------------------------------------

def _read_lines(path: str) -> list[str]:
    """Return the lines of a name file that are not blank, stripped

    @param path  a file such as `formula_names.txt`
    @returns     the lines; empty when the file cannot be read
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [line.strip() for line in fh if line.strip()]
    except OSError:
        return []


def newest_api_file(api_dir: str, arch: str) -> str | None:
    """Return the newest API file of `api_dir` for the instance's architecture

    The files are `internal/packages.<tag>.jws.json`: `arm64_*` tags for an arm64 instance, the others for
    x86_64, never a `_linux` tag.

    @param api_dir  the instance's `<cache_dir>/api`
    @param arch     the instance's architecture, `arm64` or `x86_64`
    @returns        the newest such file by mtime, or None
    """
    found = []
    for path in glob.glob(os.path.join(api_dir, "internal", "packages.*.jws.json")):
        tag = os.path.basename(path)[len("packages."):-len(".jws.json")]
        if tag.endswith("_linux") or tag.startswith("arm64_") != (arch == "arm64"):
            continue
        try:
            found.append((os.stat(path).st_mtime, path))
        except OSError:
            continue
    return max(found)[1] if found else None


def _table(payload: Mapping[str, Any], key: str, kind: type) -> dict[str, Any]:
    """Return one member of the payload with only the entries of the expected type

    @param payload  the decoded API payload
    @param key      the member, such as `formulae` or `formula_renames`
    @param kind     the type each entry must have, `dict` or `str`
    @returns        the member's entries of that type, keyed by string; empty when the member is not a dict
    """
    value = payload.get(key)
    if not isinstance(value, dict):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, kind)}


def read_payload(path: str) -> dict[str, Any]:
    """Return the payload of an API file, JSON whose `payload` member is itself a JSON string

    @param path         an `internal/packages.<tag>.jws.json` file
    @returns            the decoded payload
    @throws OSError     the file cannot be read
    @throws ValueError  the file is not JSON, or holds no payload object
    """
    with open(path, "rb") as fh:
        outer = json.load(fh)
    payload = outer.get("payload") if isinstance(outer, dict) else None
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} has no payload object")
    return payload


class Catalogue:
    """The offline catalogue of one Homebrew instance"""

    def __init__(self, *, formulae: dict[str, Any] | None = None, casks: dict[str, Any] | None = None,
                 formula_aliases: dict[str, str] | None = None, formula_renames: dict[str, str] | None = None,
                 formula_tap_migrations: dict[str, str] | None = None,
                 cask_renames: dict[str, str] | None = None, cask_tap_migrations: dict[str, str] | None = None,
                 formula_names: Iterable[str] = (), cask_tokens: Iterable[str] = (),
                 executables: dict[str, list[str]] | None = None, source: str = "none",
                 api_file: str | None = None, api_mtime: float | None = None, frozen: bool = False,
                 load_error: str | None = None, prefix: str = "", dirs: dict[str, str] | None = None,
                 home: str | None = None, today: datetime.date | None = None) -> None:
        """Build a catalogue from its tables, each empty by default

        @param formulae                the API entries of the formulae, by name
        @param casks                   the API entries of the casks, by token
        @param formula_aliases         formula aliases to names; the `aliases` of each entry are added
        @param formula_renames         old formula names to the names that replaced them
        @param formula_tap_migrations  formulae that migrated to another tap, to that tap
        @param cask_renames            old cask tokens to the tokens that replaced them
        @param cask_tap_migrations     casks that migrated to another tap, to that tap
        @param formula_names           formula names beside those of `formulae`
        @param cask_tokens             cask tokens beside those of `casks`
        @param executables             formula names to the executables they install
        @param source                  api, taps, names or none
        @param api_file                the API file read, or None
        @param api_mtime               the newest per-arch API file's mtime, for the stale-catalogue finding
        @param frozen                  whether HOMEBREW_NO_INSTALL_FROM_API is in effect for the instance
        @param load_error              why the API file could not be read, or None
        @param prefix                  the instance's prefix
        @param dirs                    the cask artifact directories by key; None expands `DEFAULT_CASK_DIRS`
        @param home                    the user's home; None for the current user's
        @param today                   the date deprecations and disables are judged on; None for the current date
        """
        self._formulae = dict(formulae or {})
        self._casks = dict(casks or {})
        self._aliases = dict(formula_aliases or {})
        for name, entry in self._formulae.items():
            for alias in _as_list(entry.get("aliases")):
                self._aliases.setdefault(str(alias), name)
        self._formula_renames = dict(formula_renames or {})
        self._formula_migrations = dict(formula_tap_migrations or {})
        self._cask_renames = dict(cask_renames or {})
        self._cask_migrations = dict(cask_tap_migrations or {})
        self._formula_names = frozenset(set(self._formulae) | set(formula_names))
        self._cask_tokens = frozenset(set(self._casks) | set(cask_tokens))
        self._executables = dict(executables or {})
        self.source = source                    # "api", "taps", "names" or "none"
        self.api_file = api_file
        self.api_mtime = api_mtime              # the newest per-arch API file's, for the stale-catalogue finding
        self.frozen = frozen                    # HOMEBREW_NO_INSTALL_FROM_API is in effect for the instance
        self.load_error = load_error
        self.prefix = prefix
        self.home = home or os.path.expanduser("~")
        self.dirs = dict(dirs or {key: expand_path(v, prefix, {}, self.home)
                                  for key, v in DEFAULT_CASK_DIRS.items()})
        self.today = today
        self._oldnames: dict[str, str] | None = None
        self._by_exe: dict[str, list[str]] | None = None
        self._by_homepage: dict[str, list[tuple[str, str]]] | None = None
        self._cask_info: dict[str, CaskInfo | None] = {}

    @property
    def degraded(self) -> bool:
        """Return whether homepages, executables, renames or bottle data are unavailable

        @returns  True for a catalogue read from anything but the API
        """
        return self.source != "api"

    def _today(self) -> datetime.date:
        """Return the date deprecations and disables are judged on

        @returns  the catalogue's `today`, else the current date
        """
        return self.today or datetime.date.today()

    # Loading -----------------------------------------------------------------------

    @classmethod
    def load(cls, instance: model.Instance, environ: Mapping[str, str] | None = None,
             host_arch: str | None = None, today: datetime.date | None = None) -> "Catalogue":
        """Read the instance's offline catalogue; downloads nothing

        The tap checkouts stand in without an API file or under `HOMEBREW_NO_INSTALL_FROM_API`.

        @param instance   the Homebrew instance
        @param environ    the environment `brew` starts with; None reads `os.environ`
        @param host_arch  the host's architecture, for an instance whose architecture is unknown
        @param today      the date deprecations and disables are judged on; None for the current date
        @returns          the catalogue, its `source` naming what it holds
        """
        env = dict(os.environ if environ is None else environ)
        home = env.get("HOME") or os.path.expanduser("~")
        lines = locate.brew_env_lines(instance.prefix, env)
        frozen = bool(locate.effective("HOMEBREW_NO_INSTALL_FROM_API", env, lines))
        common: dict[str, Any] = {"prefix": instance.prefix, "dirs": cask_dirs(instance.prefix, env, lines, home),
                                  "home": home, "today": today, "frozen": frozen}
        api_dir = os.path.join(instance.cache_dir or locate.default_cache_dir(env), "api")
        arch = instance.arch or host_arch or "arm64"
        repository = instance.repository or locate.repository_of(instance.prefix)
        taps = os.path.join(repository, "Library", "Taps", "homebrew")
        api_file = newest_api_file(api_dir, arch)
        if (frozen or api_file is None) and os.path.isdir(os.path.join(taps, "homebrew-core")):
            return cls.from_taps(taps, **common)
        load_error = None
        if api_file is not None:
            try:
                payload = read_payload(api_file)
                return cls.from_payload(payload, api_dir=api_dir, api_file=api_file,
                                        api_mtime=os.stat(api_file).st_mtime, **common)
            except (OSError, ValueError) as exc:
                load_error = f"{api_file}: {exc}"
        return cls.from_payload({}, api_dir=api_dir, source="names", load_error=load_error, **common)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any], api_dir: str | None = None, source: str = "api",
                     **kwargs: Any) -> "Catalogue":
        """Build a catalogue from a decoded payload and the name files of `api_dir`

        @param payload  the decoded API payload; empty for a catalogue of names only
        @param api_dir  the `<cache_dir>/api` whose name files add names, aliases and executables, or None
        @param source   `api`, or `names` for a catalogue without a payload, which becomes `none` without names
        @param kwargs   further `Catalogue` arguments, such as `prefix` and `dirs`
        @returns        the catalogue
        """
        names: list[str] = []
        tokens: list[str] = []
        aliases: dict[str, str] = {}
        executables: dict[str, list[str]] = {}
        if api_dir:
            names = _read_lines(os.path.join(api_dir, "formula_names.txt"))
            tokens = _read_lines(os.path.join(api_dir, "cask_names.txt"))
            for line in _read_lines(os.path.join(api_dir, "formula_aliases.txt")):
                alias, sep, target = line.partition("|")
                if sep:
                    aliases[alias] = target
            for line in _read_lines(os.path.join(api_dir, "internal", "executables.txt")):
                name, sep, exes = line.partition(":")
                if sep:
                    executables[name] = exes.split()
        aliases.update(_table(payload, "formula_aliases", str))
        if source == "names" and not (names or tokens or aliases or executables):
            source = "none"
        return cls(formulae=_table(payload, "formulae", dict), casks=_table(payload, "casks", dict),
                   formula_aliases=aliases, formula_renames=_table(payload, "formula_renames", str),
                   formula_tap_migrations=_table(payload, "formula_tap_migrations", str),
                   cask_renames=_table(payload, "cask_renames", str),
                   cask_tap_migrations=_table(payload, "cask_tap_migrations", str),
                   formula_names=names, cask_tokens=tokens, executables=executables, source=source, **kwargs)

    @classmethod
    def from_taps(cls, taps_dir: str, **kwargs: Any) -> "Catalogue":
        """Build the tap-checkout fallback catalogue, of names and aliases only

        Formula names come from the `.rb` files in `homebrew-core/Formula` and one directory level below it,
        aliases from the `Aliases/` links, cask tokens likewise from `homebrew-cask/Casks`.

        @param taps_dir  the repository's `Library/Taps/homebrew`
        @param kwargs    further `Catalogue` arguments, such as `prefix` and `dirs`
        @returns         the catalogue
        """
        core = os.path.join(taps_dir, "homebrew-core")
        cask = os.path.join(taps_dir, "homebrew-cask")

        def rb_names(directory: str) -> list[str]:
            files = glob.glob(os.path.join(directory, "*.rb")) + glob.glob(os.path.join(directory, "*", "*.rb"))
            return [os.path.basename(f)[:-3] for f in files]

        aliases: dict[str, str] = {}
        alias_dir = os.path.join(core, "Aliases")
        try:
            entries = sorted(os.listdir(alias_dir))
        except OSError:
            entries = []
        for alias in entries:
            path = os.path.join(alias_dir, alias)
            try:
                target = os.readlink(path)
            except OSError:
                continue
            if target.endswith(".rb"):
                aliases[alias] = os.path.basename(target)[:-3]
        return cls(formula_names=rb_names(os.path.join(core, "Formula")), formula_aliases=aliases,
                   cask_tokens=rb_names(os.path.join(cask, "Casks")), source="taps", **kwargs)

    # Names --------------------------------------------------------------------------

    def formula_names(self) -> frozenset:
        """Return every formula name the catalogue knows

        @returns  the names of the payload, the name files or the tap checkouts
        """
        return self._formula_names

    def cask_tokens(self) -> frozenset:
        """Return every cask token the catalogue knows

        @returns  the tokens of the payload, the name files or the tap checkouts
        """
        return self._cask_tokens

    @staticmethod
    def _follow(mapping: Mapping[str, str], name: str) -> str:
        """Follow a chain of renames to its end, stopping at a cycle

        @param mapping  old names to the names that replaced them
        @param name     the name to start from
        @returns        the last name of the chain; `name` itself when it is not renamed
        """
        seen: set[str] = set()
        while name in mapping and name not in seen:
            seen.add(name)
            name = mapping[name]
        return name

    def _oldname_index(self) -> dict[str, str]:
        """Return the formulae's `oldnames`, each mapped to the formula that lists it, built on first use

        @returns  old names to formula names; the first formula that lists a name keeps it
        """
        if self._oldnames is None:
            self._oldnames = {}
            for name, entry in self._formulae.items():
                for old in _as_list(entry.get("oldnames")):
                    self._oldnames.setdefault(str(old), name)
        return self._oldnames

    def canonical(self, name: str, kind: str = "formula") -> str | None:
        """Return the current name of a formula or cask token; None when the catalogue does not know it

        A formula goes through aliases, renames and `oldnames`, a cask token through `cask_renames`.

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`
        @returns     the name the catalogue lists, or None
        """
        if kind == "cask":
            token = self._follow(self._cask_renames, name)
            return token if token in self._cask_tokens else None
        if name in self._formula_names:
            return name
        for candidate in (self._aliases.get(name), self._follow(self._formula_renames, name),
                          self._oldname_index().get(name)):
            if candidate and candidate in self._formula_names:
                return candidate
        return None

    def knows(self, name: str, kind: str = "formula") -> bool:
        """Return whether the catalogue knows a formula or cask by any of its names

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`
        @returns     True when `canonical` finds it
        """
        return self.canonical(name, kind) is not None

    def renamed_to(self, name: str, kind: str = "formula") -> str | None:
        """Return the `formula_renames` (or `cask_renames`) entry for `name`, followed to its end

        @param name  a formula name or cask token, perhaps an old one
        @param kind  `formula` or `cask`
        @returns     the name at the end of the renames, or None when `name` is not renamed
        """
        mapping = self._cask_renames if kind == "cask" else self._formula_renames
        new = self._follow(mapping, name)
        return new if new != name else None

    def alias_target(self, name: str) -> str | None:
        """Return the formula a formula alias names

        @param name  a formula alias
        @returns     the formula name, or None when `name` is not an alias
        """
        return self._aliases.get(name)

    def tap_migration(self, name: str, kind: str = "formula") -> str | None:
        """Return the tap a formula or cask migrated to (`formula_tap_migrations`, `cask_tap_migrations`)

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`
        @returns     the tap, or None when the catalogue lists no migration
        """
        return (self._cask_migrations if kind == "cask" else self._formula_migrations).get(name)

    # Entries ---------------------------------------------------------------------

    def formula(self, name: str) -> dict[str, Any] | None:
        """Return the payload entry of a formula, looked up through `canonical()`

        @param name  a formula name, alias or old name
        @returns     the entry, or None when the payload has none
        """
        entry = self._formulae.get(name)
        if entry is None:
            canon = self.canonical(name)
            entry = self._formulae.get(canon) if canon else None
        return entry

    def _cask_entry(self, token: str) -> dict[str, Any] | None:
        """Return the payload entry of a cask, looked up through `canonical()`

        @param token  a cask token, perhaps an old one
        @returns      the entry, or None when the payload has none
        """
        entry = self._casks.get(token)
        if entry is None:
            canon = self.canonical(token, "cask")
            entry = self._casks.get(canon) if canon else None
        return entry

    def _entry(self, name: str, kind: str) -> dict[str, Any] | None:
        """Return the payload entry of a formula or cask

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`
        @returns     the entry, or None when the payload has none
        """
        return self._cask_entry(name) if kind == "cask" else self.formula(name)

    def cask(self, token: str) -> CaskInfo | None:
        """Return a cask with its normalised `raw_artifacts` and both privileged flags

        The flags are known for a target cask that is not installed yet; each token's answer is kept.

        @param token  a cask token, perhaps an old one
        @returns      the cask, or None when the payload has no entry for it
        """
        if token in self._cask_info:
            return self._cask_info[token]
        entry = self._cask_entry(token)
        info = None
        if entry is not None:
            artifacts = normalise_artifacts(entry.get("raw_artifacts"))
            ctx = PrivilegeContext(prefix=self.prefix, dirs=self.dirs, home=self.home, uid=os.geteuid())
            install, uninstall = privileged_flags(artifacts, ctx)
            formulae, casks = depends_lists(entry.get("depends_on_args"))
            info = CaskInfo(token=self.canonical(token, "cask") or token, version=entry.get("version"),
                            homepage=entry.get("homepage"), desc=entry.get("desc"), tap=entry.get("tap_string"),
                            artifacts=artifacts, depends_formula=formulae, depends_cask=casks,
                            auto_updates=bool(entry.get("auto_updates")), privileged_install=install,
                            privileged_uninstall=uninstall)
        self._cask_info[token] = info
        return info

    def homepage(self, name: str, kind: str = "formula") -> str | None:
        """Return the homepage of a formula or cask

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`
        @returns     the homepage, or None when the payload has none
        """
        entry = self._entry(name, kind)
        return entry.get("homepage") if entry else None

    def desc(self, name: str, kind: str = "formula") -> str | None:
        """Return the one-line description of a formula or cask

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`
        @returns     the description, or None when the payload has none
        """
        entry = self._entry(name, kind)
        return entry.get("desc") if entry else None

    def version(self, name: str, kind: str = "formula") -> str | None:
        """Return the catalogue version: a formula's `stable_version` with its `_revision`, a cask's `version`

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`
        @returns     the version, or None when the payload has none
        """
        entry = self._entry(name, kind)
        if not entry:
            return None
        if kind == "cask":
            return entry.get("version")
        version = entry.get("stable_version")
        if version and entry.get("revision"):
            return f"{version}_{int(entry['revision'])}"
        return version

    def keg_only(self, name: str) -> bool:
        """Return whether a formula is keg-only

        @param name  a formula name
        @returns     True when its entry has `keg_only_args`
        """
        entry = self.formula(name)
        return entry is not None and "keg_only_args" in entry

    def has_bottle(self, name: str) -> bool:
        """Return whether the formula has a bottle

        The test reads `bottle_checksum`: relocatable bottles have no `bottle_cellar`.

        @param name  a formula name
        @returns     True when its entry has a bottle checksum
        """
        entry = self.formula(name)
        return entry is not None and bool(entry.get("bottle_checksum"))

    def python_dependencies(self, name: str) -> list[str]:
        """Return every `python@3.X` among a formula's dependencies, in listed order, whatever its tags

        @param name  a formula name
        @returns     the Python formulae; empty for a formula the payload lacks
        """
        entry = self.formula(name)
        out: list[str] = []
        for dep in (entry or {}).get("stable_dependencies") or []:
            for dep_name in ([dep] if isinstance(dep, str) else list(dep) if isinstance(dep, dict) else []):
                if _PYTHON.match(dep_name) and dep_name not in out:
                    out.append(dep_name)
        return out

    def executables(self, name: str) -> list[str]:
        """Return the executables a formula installs, from its entry and `executables.txt`

        @param name  a formula name
        @returns     the executable names, the entry's first; empty when none is known
        """
        entry = self.formula(name)
        canon = self.canonical(name) or name
        out = list((entry or {}).get("executables") or [])
        for exe in self._executables.get(canon, []):
            if exe not in out:
                out.append(exe)
        return out

    def by_executable(self, exe: str) -> list[str]:
        """Return the formulae that install an executable of that name (`executables.txt`, payload)

        @param exe  an executable's name
        @returns    the formula names, sorted
        """
        if self._by_exe is None:
            index: dict[str, list[str]] = {}
            names = set(self._executables) | set(self._formulae)
            for name in sorted(names):
                for item in self.executables(name):
                    index.setdefault(item, []).append(name)
            self._by_exe = index
        return list(self._by_exe.get(exe, []))

    def by_homepage(self, url: str) -> list[tuple[str, str]]:
        """Return `(kind, name)` of every formula and cask with the same normalised homepage

        @param url  a homepage URL
        @returns    the matches, the formulae first, each kind sorted by name
        """
        if self._by_homepage is None:
            index: dict[str, list[tuple[str, str]]] = {}
            for kind, entries in (("formula", self._formulae), ("cask", self._casks)):
                for name in sorted(entries):
                    key = normalise_url(entries[name].get("homepage"))
                    if key:
                        index.setdefault(key, []).append((kind, name))
            self._by_homepage = index
        return list(self._by_homepage.get(normalise_url(url) or "", []))

    # Lifecycle ---------------------------------------------------------------------

    def deprecated(self, name: str, kind: str = "formula") -> bool:
        """Return whether a formula or cask is deprecated on the catalogue's date

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`
        @returns     True when `lifecycle` deprecates its entry; False for one the payload lacks
        """
        entry = self._entry(name, kind)
        return entry is not None and lifecycle(entry, self._today(), kind)[0]

    def disabled(self, name: str, kind: str = "formula") -> bool:
        """Return whether a formula or cask is disabled on the catalogue's date

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`
        @returns     True when `lifecycle` disables its entry; False for one the payload lacks
        """
        entry = self._entry(name, kind)
        return entry is not None and lifecycle(entry, self._today(), kind)[1]

    def refused(self, name: str, kind: str = "formula") -> dict[str, Any] | None:
        """Return why Homebrew refuses to install the entry today, or None

        It refuses an entry whose `disable_args` date has passed and that is not deprecated.

        @param name  a formula name or cask token
        @param kind  `formula` or `cask`
        @returns     the `date`, `because`, `replacement_formula` and `replacement_cask` of its `disable_args`,
                     or None
        """
        entry = self._entry(name, kind)
        if not entry:
            return None
        deprecated, disabled = lifecycle(entry, self._today(), kind)
        if not disabled or deprecated:
            return None
        args = plain_keys(entry["disable_args"])
        return {"date": args.get("date"), "because": plain_symbol(args.get("because")),
                "replacement_formula": args.get("replacement_formula"),
                "replacement_cask": args.get("replacement_cask")}

    # Services ---------------------------------------------------------------------

    def service_labels(self) -> dict[str, str]:
        """Return every launchd label a catalogue formula can own, mapped to that formula

        The labels are `sh.brew.<f>`, the legacy `homebrew.mxcl.<f>`, and the `:macos` value of `service_name_args`,
        which wins over a generated label of the same text. A formula also owns the generated labels of each old
        name `formula_renames` or its `oldnames` give it, since a job started before a rename keeps its label;
        an alias is no old name.

        @returns  the labels, each to its formula
        """
        labels: dict[str, str] = {}
        for old in sorted(set(self._formula_renames) | set(self._oldname_index())):
            renamed = (self._follow(self._formula_renames, old), self._oldname_index().get(old))
            name = next((n for n in renamed if n in self._formula_names), None)
            if name is not None:
                labels["sh.brew." + old] = name
                labels["homebrew.mxcl." + old] = name
        for name in sorted(self._formula_names):
            labels["sh.brew." + name] = name
            labels["homebrew.mxcl." + name] = name
        for name, entry in sorted(self._formulae.items()):
            args = plain_keys(entry.get("service_name_args"))
            if isinstance(args, dict) and isinstance(args.get("macos"), str):
                labels[args["macos"]] = name
        return labels

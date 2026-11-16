"""Locating Homebrew instances, their usability, the target choice and the `brew.env` lines `bin/brew` exports"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .. import model, system
from ..runner import Result, arch_argv
from ..state import slug
from . import actions

ARM64_PREFIX = "/opt/homebrew"
USR_LOCAL = "/usr/local"
LIPO = system.LIPO
SYSTEM_BREW_ENV = "/etc/homebrew/brew.env"
PORTABLE_RUBY = os.path.join("Library", "Homebrew", "vendor", "portable-ruby", "current", "bin", "ruby")
USR_LOCAL_SUBTREES = ("Cellar", "Caskroom", "Homebrew", "opt", os.path.join("var", "homebrew"))
CACHE_SUBDIR = os.path.join("Library", "Caches", "Homebrew")

Identity = tuple[int, int]


def _home(environ: Mapping[str, str]) -> str:
    """Return the home directory: `HOME` from the environment, else the one `os.path.expanduser` finds

    @param environ  the environment the tool runs with
    @returns        the home directory's path
    """
    return environ.get("HOME") or os.path.expanduser("~")


def default_cache_dir(environ: Mapping[str, str]) -> str:
    """Return `~/Library/Caches/Homebrew`, the cache of an instance that is not drivable

    @param environ  the environment, whose `HOME` names the home directory
    @returns        the cache directory's path
    """
    return os.path.join(_home(environ), CACHE_SUBDIR)


def repository_of(prefix: str) -> str:
    """Return the repository: the prefix when it holds `Library/Homebrew`, else `<prefix>/Homebrew`

    `/usr/local` keeps its repository in `/usr/local/Homebrew`.

    @param prefix  the Homebrew prefix
    @returns       the repository's path
    """
    if os.path.isdir(os.path.join(prefix, "Library", "Homebrew")):
        return prefix
    return os.path.join(prefix, "Homebrew")


def portable_ruby(repository: str) -> str:
    """Return the path of the portable Ruby that runs a repository's `brew`

    @param repository  the Homebrew repository
    @returns           `<repository>/Library/Homebrew/vendor/portable-ruby/current/bin/ruby`
    """
    return os.path.join(repository, PORTABLE_RUBY)


def is_usr_local(prefix: str) -> bool:
    """Return whether a prefix is the directory `/usr/local`, compared by identity

    @param prefix  a Homebrew prefix, in any spelling
    @returns       True when the prefix and `/usr/local` share one `(st_dev, st_ino)`
    """
    ident = system.identity(prefix)
    return ident is not None and ident == system.identity(USR_LOCAL)


def owned_roots(prefix: str) -> tuple[str, ...]:
    """Return the prefix itself, or Homebrew's own subtrees of `/usr/local`

    Other installers share `/usr/local`: Go, TeX Live, the .NET SDK, python.org links.

    @param prefix  the Homebrew prefix
    @returns       the roots the instance owns
    """
    if is_usr_local(prefix):
        return tuple(os.path.join(prefix, sub) for sub in USR_LOCAL_SUBTREES)
    return (prefix,)


def owns_path(instance: model.Instance, path: str) -> bool:
    """Return whether `path`, after `os.path.realpath`, lies in one of the instance's `owned_roots`, by identity

    @param instance  the Homebrew instance
    @param path      the path to test, in any spelling
    @returns         True when the path lies under one of the roots
    """
    for root in instance.owned_roots:
        ident = system.identity(root)
        if ident is not None and system.lies_under(path, ident):
            return True
    return False


# Candidates -----------------------------------------------------------------

def _brew_on_path(environ: Mapping[str, str]) -> str | None:
    """Return the first `brew` with an execute bit in the PATH directories, as a shell finds it

    @param environ  the environment whose `PATH` is searched
    @returns        the path of that `brew`, or None
    """
    for entry in environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        candidate = os.path.join(entry, "brew")
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_mode & 0o111:
            return candidate
    return None


def _holds_homebrew(prefix: str) -> bool:
    """Return whether a prefix found through PATH or `HOMEBREW_PREFIX` holds a repository or a Cellar

    The test keeps a wrapper script named `brew` from making an instance.

    @param prefix  the candidate prefix
    @returns       True when it holds `Library/Homebrew`, `Homebrew/Library/Homebrew` or `Cellar`
    """
    return (os.path.isdir(os.path.join(prefix, "Library", "Homebrew"))
            or os.path.isdir(os.path.join(prefix, "Homebrew", "Library", "Homebrew"))
            or os.path.isdir(os.path.join(prefix, "Cellar")))


def candidate_prefixes(environ: Mapping[str, str]) -> list[str]:
    """Return the candidate prefixes in order, one directory possibly more than once

    The order: `/opt/homebrew` and `/usr/local` with a `bin/brew`, the `brew` first on PATH, `HOMEBREW_PREFIX`,
    then `/usr/local` when it holds a Cellar or a repository.

    @param environ  the environment, for `PATH` and `HOMEBREW_PREFIX`
    @returns        the prefixes, in that order
    """
    found: list[str] = []
    for prefix in (ARM64_PREFIX, USR_LOCAL):
        if os.path.isfile(os.path.join(prefix, "bin", "brew")):
            found.append(prefix)
    on_path = _brew_on_path(environ)
    if on_path:
        prefix = os.path.normpath(os.path.dirname(os.path.dirname(on_path)))
        if _holds_homebrew(prefix):
            found.append(prefix)
    env_prefix = environ.get("HOMEBREW_PREFIX")
    if env_prefix and os.path.isabs(env_prefix):
        env_prefix = os.path.normpath(env_prefix)
        if os.path.isdir(env_prefix) and _holds_homebrew(env_prefix):
            found.append(env_prefix)
    if any(os.path.isdir(os.path.join(USR_LOCAL, sub)) for sub in ("Cellar", "Homebrew")):
        found.append(USR_LOCAL)
    return found


def group_by_identity(spellings: Sequence[str]) -> list[tuple[Identity, list[str]]]:
    """Group the spellings by `(st_dev, st_ino)`, each group named by its first spelling

    A case variant or the `/System/Volumes/Data` spelling of a prefix joins the group of the same directory;
    the realpath is recorded as one more spelling.

    @param spellings  prefix spellings, in candidate order
    @returns          one `(identity, spellings)` pair per existing directory, in the order first met
    """
    groups: list[tuple[Identity, list[str]]] = []
    for spelling in spellings:
        ident = system.identity(spelling)
        if ident is None:
            continue
        for known, names in groups:
            if known == ident:
                if spelling not in names:
                    names.append(spelling)
                break
        else:
            groups.append((ident, [spelling]))
    for _, names in groups:
        real = os.path.realpath(names[0])
        if real not in names:
            names.append(real)
    return groups


# Probes ---------------------------------------------------------------------

def failure_text(result: Result, what: str) -> str:
    """Return the error text of a failed probe, as `usability_detail`, an inventory error or a finding records it

    @param result  the probe's result
    @param what    the probe, as the text names it
    @returns       `<what> timed out`, or `<what> failed with exit <n>` and the last lines of the probe's output
    """
    if result.timed_out:
        return f"{what} timed out"
    text = result.stderr().strip() or result.stdout().strip()
    lines = [line for line in text.splitlines() if line.strip()]
    detail = "\n".join(lines[-20:])[-2000:]
    return f"{what} failed with exit {result.exit}" + (f": {detail}" if detail else "")


def parse_archs(text: str, host_arch: str) -> str | None:
    """Parse `lipo -archs` output into one architecture; a universal file counts as the host's

    @param text       the output of `lipo -archs`
    @param host_arch  the host's architecture, the pick from a universal file that holds it
    @returns          the architecture, an `arm64e` slice read as `arm64`; None when the output names none
    """
    archs: list[str] = []
    for word in text.split():
        word = "arm64" if word.startswith("arm64") else word
        if word not in archs:
            archs.append(word)
    if not archs:
        return None
    if len(archs) > 1:
        return host_arch if host_arch in archs else archs[0]
    return archs[0]


def ruby_arch(runner, action_id: str, ruby: str, host_arch: str) -> str | None:
    """Probe the instance's architecture with `lipo -archs` of its portable Ruby, before any other probe

    @param runner     the runner the probe goes through
    @param action_id  the probe's action id, `0.brew.<subject>.lipo`
    @param ruby       the portable Ruby's path
    @param host_arch  the host's architecture, the pick from a universal Ruby
    @returns          the Ruby's architecture, or None when `lipo` fails or names none
    """
    res = runner.run(system.probe(action_id, [LIPO, "-archs", ruby], "architecture of Homebrew's portable Ruby"))
    if res.exit != 0 or res.timed_out:
        return None
    return parse_archs(res.stdout(), host_arch)


def config_value(text: str, key: str) -> str | None:
    """Return the value of one `KEY: value` line of `brew config`

    @param text  the output of `brew config`
    @param key   the key, such as `HOMEBREW_VERSION`
    @returns     the value, or None when the key is absent or empty
    """
    for line in text.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip() == key:
            return value.strip() or None
    return None


def _set(instance: model.Instance, usability: model.Usability, detail: str | None) -> None:
    """Record an instance's usability, which also decides whether it is drivable

    @param instance   the Homebrew instance
    @param usability  the probes' verdict
    @param detail     the error text, or None for a usable instance
    """
    instance.usability = usability
    instance.usability_detail = detail
    instance.drivable = usability is model.Usability.USABLE


def probe_instance(runner, prefix: str, ident: Identity, spellings: Sequence[str], *,
                   environ: Mapping[str, str], host_arch: str) -> model.Instance:
    """Probe the instance at `prefix`: its architecture, the Ruby probe, then `brew config` and `brew --cache`

    Without a working portable Ruby no `brew` runs at all, because `brew` would download one.

    @param runner     the runner the probes go through
    @param prefix     the Homebrew prefix, by the first spelling of its group
    @param ident      the prefix's `(st_dev, st_ino)`
    @param spellings  every spelling met for the prefix
    @param environ    the environment, for the default download cache
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @returns          the instance, with its usability
    """
    brew = os.path.join(prefix, "bin", "brew")
    repository = repository_of(prefix)
    ruby = portable_ruby(repository)
    subject = slug(prefix)
    arch = ruby_arch(runner, f"0.brew.{subject}.lipo", ruby, host_arch) if os.path.lexists(ruby) else None
    instance = model.Instance(
        manager=model.Manager.BREW, prefix=prefix, identity=ident, spellings=tuple(spellings),
        binary=brew if os.path.isfile(brew) else None, version=None, arch=arch,
        usability=model.Usability.CANNOT_RUN, usability_detail=None, drivable=False, inventory_error=None,
        repository=repository, cache_dir=default_cache_dir(environ), portdbpath=None, applications_dir=None,
        owned_roots=owned_roots(prefix))
    if instance.binary is None:
        _set(instance, model.Usability.MISSING_BINARY, f"{brew} is missing")
        return instance
    if not os.path.isfile(ruby):
        _set(instance, model.Usability.CANNOT_RUN, f"Homebrew's portable Ruby is missing: {ruby}")
        return instance
    res = runner.run(system.probe(f"0.brew.{subject}.ruby", arch_argv(arch, host_arch, [ruby, "-e", "exit 0"]),
                                  "Homebrew's portable Ruby runs"))
    if res.exit != 0 or res.timed_out:
        _set(instance, model.Usability.CANNOT_RUN, failure_text(res, "Homebrew's portable Ruby"))
        return instance
    res = runner.run(actions.config(instance, host_arch, f"0.brew.{subject}.config"))
    if res.exit != 0 or res.timed_out:
        _set(instance, model.Usability.CANNOT_RUN, failure_text(res, "brew config"))
        return instance
    instance.version = config_value(res.stdout(), "HOMEBREW_VERSION")
    _set(instance, model.Usability.USABLE, None)
    res = runner.run(actions.cache(instance, host_arch, f"0.brew.{subject}.cache"))
    lines = [line.strip() for line in res.stdout().splitlines() if line.strip()]
    if res.exit == 0 and not res.timed_out and lines and os.path.isabs(lines[-1]):
        instance.cache_dir = lines[-1]
    return instance


def find_instances(runner, environ: Mapping[str, str], host_arch: str) -> list[model.Instance]:
    """Find every Homebrew instance on the host, one per prefix identity

    @param runner     the runner the probes go through
    @param environ    the environment, for `PATH`, `HOMEBREW_PREFIX` and the default download cache
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @returns          the probed instances, in candidate order
    """
    return [probe_instance(runner, names[0], ident, names, environ=environ, host_arch=host_arch)
            for ident, names in group_by_identity(candidate_prefixes(environ))]


# Target choice --------------------------------------------------------------

def find_by_path(instances: Sequence[model.Instance], path: str) -> model.Instance | None:
    """Find the instance whose prefix is `path`: by identity, or by its recorded spellings when the path is gone

    @param instances  the instances to search
    @param path       a prefix, in any spelling
    @returns          the instance, or None
    """
    ident = system.identity(path)
    if ident is not None:
        for inst in instances:
            if tuple(inst.identity) == ident:
                return inst
        return None
    for inst in instances:
        fold = system.case_insensitive(inst.prefix)
        wanted = system.normalise_text_path(path, fold)
        if any(system.normalise_text_path(s, fold) == wanted for s in inst.spellings):
            return inst
    return None


def choose_target(instances: Sequence[model.Instance], host_arch: str, target_prefix: str | None,
                  environ: Mapping[str, str]) -> model.Instance | None:
    """Choose the Homebrew target of a `ports -> brew` plan

    With `--target-prefix`, the instance there, drivable or not; without it, the drivable one at the host's default
    prefix, else the drivable one at `HOMEBREW_PREFIX`.

    @param instances      the instances found on the host
    @param host_arch      the host's architecture, which decides the default prefix
    @param target_prefix  the `--target-prefix` value, or None
    @param environ        the environment, for `HOMEBREW_PREFIX`
    @returns              the target, or None when no instance qualifies
    """
    brews = [i for i in instances if i.manager is model.Manager.BREW]
    if target_prefix:
        return find_by_path(brews, target_prefix)
    default = ARM64_PREFIX if host_arch == "arm64" else USR_LOCAL
    for path in (default, environ.get("HOMEBREW_PREFIX")):
        if not path:
            continue
        inst = find_by_path(brews, path)
        if inst is not None and inst.drivable:
            return inst
    return None


# brew.env -------------------------------------------------------------------

@dataclass
class EnvLine:
    """One assignment that `bin/brew` exports from a `brew.env` file, with the file and line it came from"""
    path: str
    lineno: int
    name: str
    value: str


BIN_BREW_EXPORTED = frozenset(("HOMEBREW_BREW_FILE", "HOMEBREW_PREFIX", "HOMEBREW_REPOSITORY",
                               "HOMEBREW_LIBRARY", "HOMEBREW_USER_CONFIG_HOME"))
_EXPORTED_LINE = re.compile(r"^(HOMEBREW_|SUDO_ASKPASS=|(all|no|ftp|https?)_proxy=)")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def brew_env_files(prefix: str, environ: Mapping[str, str]) -> list[str]:
    """Return the three `brew.env` files `bin/brew` reads, in its order: system, prefix and user

    @param prefix   the Homebrew prefix
    @param environ  the environment, for `XDG_CONFIG_HOME`, `HOMEBREW_XDG_CONFIG_HOME` and `HOME`
    @returns        the three paths, whether the files exist or not
    """
    if environ.get("XDG_CONFIG_HOME"):
        user = os.path.join(environ["XDG_CONFIG_HOME"], "homebrew")
    elif environ.get("HOMEBREW_XDG_CONFIG_HOME"):
        user = os.path.join(environ["HOMEBREW_XDG_CONFIG_HOME"], "homebrew")
    else:
        user = os.path.join(_home(environ), ".homebrew")
    return [SYSTEM_BREW_ENV, os.path.join(prefix, "etc", "homebrew", "brew.env"), os.path.join(user, "brew.env")]


def read_env_file(path: str) -> list[EnvLine]:
    """Read the lines of one file that `bin/brew`'s `while read -r line` loop exports

    `read -r` trims spaces and tabs and drops a last line without a newline; only assignments of `HOMEBREW_*`,
    `SUDO_ASKPASS` and lower-case proxies count, but not the ones `bin/brew` sets itself.

    @param path  a `brew.env` file
    @returns     the exported lines in file order; empty when the file cannot be read
    """
    try:
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    out: list[EnvLine] = []
    for lineno, raw in enumerate(text.split("\n")[:-1], start=1):
        line = raw.strip(" \t")
        if not _EXPORTED_LINE.match(line):
            continue
        name, sep, value = line.partition("=")
        if not sep or not _IDENTIFIER.match(name) or name in BIN_BREW_EXPORTED:
            continue
        if name == "HOMEBREW_EXPERIMENTAL_RUST_FRONTEND":   # bin/brew ignores it in an env file
            continue
        out.append(EnvLine(path=path, lineno=lineno, name=name, value=value))
    return out


def effective(name: str, environ: Mapping[str, str], lines: Sequence[EnvLine]) -> str | None:
    """Return the value `brew` sees: the last exported line for `name`, else the environment

    @param name     the variable, such as `HOMEBREW_NO_AUTO_UPDATE`
    @param environ  the environment `brew` starts with
    @param lines    the exported lines, in load order
    @returns        the value, or None when neither sets it
    """
    for line in reversed(list(lines)):
        if line.name == name:
            return line.value
    return environ.get(name)


def brew_env_lines(prefix: str, environ: Mapping[str, str]) -> list[EnvLine]:
    """Return every line `bin/brew` exports over the environment, in load order

    The system, prefix and user files, then the system file again when it or the environment sets
    `HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY`.

    @param prefix   the Homebrew prefix
    @param environ  the environment `brew` starts with
    @returns        the exported lines
    """
    system_file, prefix_file, user_file = brew_env_files(prefix, environ)
    first = read_env_file(system_file)
    lines = first + read_env_file(prefix_file) + read_env_file(user_file)
    if effective("HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY", environ, first):
        lines += read_env_file(system_file)
    return lines

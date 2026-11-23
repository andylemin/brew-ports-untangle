"""What the unregistered-file check of the MacPorts health module walks, and what it never offers for removal

The files below a prefix, the ones every prefix generates, and the ones the packages of pip, gem, cpan and npm own.
"""

from __future__ import annotations

import glob
import os
import stat
from collections.abc import Iterator, Mapping
from typing import Any

from .. import progress

GENERATED_NAMES = frozenset(("gschemas.compiled", "mimeinfo.cache", "fonts.dir", "fonts.scale", "whatis"))
GENERATED_SUFFIXES = (".pyc", ".cache")


def walk(top: str) -> Iterator[tuple[str, os.stat_result]]:
    """Yield every entry below `top` that is not a real directory, symlinks included, with its `lstat`

    `__pycache__` directories are skipped, and an unreadable directory holds nothing.

    @param top  the directory to walk
    @returns    an iterator over the paths and their `lstat`, in name order
    """
    try:
        with os.scandir(top) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError:
        return
    progress.count(len(entries))
    for entry in entries:
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode):
            if entry.name != "__pycache__":
                yield from walk(entry.path)
        else:
            yield entry.path, st


def gem_entries(gem_dir: str, name: str | None) -> tuple[list[str], list[str]]:
    """Return the files and directories RubyGems keeps for one installed gem in its gem home

    They are `specifications/<gem>.gemspec`, `cache/<gem>.gem`, `build_info/<gem>.info` and `plugins/<name>_plugin.rb`,
    then the gem directory, `doc/<gem>/` and each `extensions/<platform>/<api version>/<gem>/`; `<gem>` is the gem
    directory's name, and the gem home holds its `gems/`.

    @param gem_dir  the gem's directory, `<gem home>/gems/<name>-<version>[-<platform>]`
    @param name     the gem's name; None when its directory's name gives none
    @returns        the files, then the directories
    """
    home, gem = os.path.dirname(os.path.dirname(gem_dir)), os.path.basename(gem_dir)
    files = [os.path.join(home, sub, gem + ext)
             for sub, ext in (("specifications", ".gemspec"), ("cache", ".gem"), ("build_info", ".info"))]
    if name:
        files.append(os.path.join(home, "plugins", name + "_plugin.rb"))
    dirs = [gem_dir, os.path.join(home, "doc", gem)]
    dirs += glob.glob(os.path.join(glob.escape(home), "extensions", "*", "*", glob.escape(gem)))
    return files, dirs


def auto_trees(path: str, module: str | None) -> list[str]:
    """Return the `auto/<Module>/` directories of a cpan module, which hold its XS parts and its `.packlist`

    They lie in the directory its module path starts in, or in an architecture directory below that one, where a
    pure-Perl module's `.packlist` goes.

    @param path    the module's `.pm` file
    @param module  the module, such as `JSON::XS`
    @returns       the directories; none when the path does not end in the module's own path
    """
    rel = (module or "").replace("::", "/")
    if not rel or not path.endswith("/" + rel + ".pm"):
        return []
    top = path[:-len(rel + ".pm")]
    return [os.path.join(top, "auto", rel)] + glob.glob(os.path.join(glob.escape(top), "*", "auto", glob.escape(rel)))


class Extras:
    """What the interpreter-extras scan attributes inside one prefix, which the stray-file removal leaves alone

    They are its `attributed` entry points; each gem with what RubyGems keeps for it; each cpan module with its
    `auto/` trees; the npm directories; and the prefix's site-packages.
    """

    def __init__(self, extras: Mapping[str, Any], prefix: str) -> None:
        """Collect the exact paths and the directory roots the extras of one prefix own

        @param extras  the interpreter-extras scan
        @param prefix  the instance's prefix
        """
        mine = {key: [item for item in extras.get(key) or [] if item.get("instance_prefix") == prefix
                      and item.get("path")] for key in ("npm", "gems", "cpan")}
        exact = list(extras.get("attributed") or []) + [item["path"] for item in mine["cpan"]]
        roots = [item["path"] for item in mine["npm"]]
        for item in mine["gems"]:
            files, dirs = gem_entries(item["path"], item.get("name"))
            exact += files
            roots += dirs
        for item in mine["cpan"]:
            roots += auto_trees(item["path"], item.get("module"))
        roots += [item["site_packages"] for item in extras.get("python") or []
                  if item.get("instance_prefix") == prefix and item.get("site_packages")]
        self.exact: set[str] = {os.path.realpath(p) for p in exact}
        self.roots = [os.path.realpath(r).rstrip("/") + "/" for r in roots]

    def owns(self, path: str) -> bool:
        """Return whether an interpreter extra owns a path, compared after symlinks are resolved

        @param path  an absolute path
        @returns     True for an attributed path or one below an owned directory
        """
        real = os.path.realpath(path)
        return real in self.exact or any(real.startswith(root) for root in self.roots)


def generated(path: str, info_dir: str) -> bool:
    """Return whether a file is one that every prefix generates, such as a cache or the info `dir`

    @param path      the file
    @param info_dir  the prefix's `share/info/dir`
    @returns         True for a generated file
    """
    name = os.path.basename(path)
    return path == info_dir or name in GENERATED_NAMES or name.endswith(GENERATED_SUFFIXES)

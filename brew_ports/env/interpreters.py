"""Interpreter extras: pip, pipx, npm, gem and cpan installs that neither manager tracks

Each vanishes with its interpreter; `requirements` builds the files a migration reinstalls them from.
"""

from __future__ import annotations

import bisect
import csv
import glob
import json
import os
import re
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from typing import Any

from .. import system
from ..model import Instance, Manager, Package
from . import PrefixIndex

CLT_FRAMEWORK = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions"
PYTHON_ORG_FRAMEWORK = "/Library/Frameworks/Python.framework/Versions"
FRAMEWORKS = (CLT_FRAMEWORK, PYTHON_ORG_FRAMEWORK)
PIPX_HOMES = (os.path.join(".local", "pipx", "venvs"), os.path.join("Library", "Application Support", "pipx", "venvs"))

_PY_SITE = re.compile(r"python(3\.\d+)$")
_PY_EXE = re.compile(r"^python(3\.\d+)$")
_VERSION_DIR = re.compile(r"^\d+(?:\.\d+)*$")
_GEM_DIR = re.compile(r"^(?P<name>.+?)-(?P<version>\d[^-]*)(?:-(?P<platform>.+))?$")
# What Homebrew's `python@3.X` installs into `<prefix>/lib/python3.X/site-packages`; before 3.12, setuptools too.
BREW_PYTHON_DISTS = ("pip", "wheel")

OwnerOf = Callable[[str], str | None]


def _glob(*parts: str) -> list[str]:
    """Return the sorted matches of a pattern tail below a base that is taken literally

    @param parts  the base directory, then the pattern's components; `**` recurses
    @returns      the matching paths, sorted
    """
    base, tail = parts[0], parts[1:]
    return sorted(glob.glob(os.path.join(glob.escape(base), *tail), recursive=True))


class _Ownership:
    """Which files in an instance's prefix its manager owns

    Homebrew owns what resolves into a keg (`<prefix>/Cellar`), and what its python formulae install into the prefix's
    site-packages; MacPorts owns its registered files (`owner_of`, else the packages' `files`).
    """

    def __init__(self, instances: Sequence[Instance], packages: Iterable[Package], owner_of: OwnerOf | None) -> None:
        """Collect the registered files of each MacPorts prefix, the Cellar identity and formulae of each Homebrew one

        @param instances  the instances
        @param packages   the inventoried packages; the ports' `files` and the formulae's names are read
        @param owner_of   returns the port that registered a path; None when no registry is read
        """
        self.owner_of = owner_of
        files: dict[str, list[str]] = {}
        self.formulae: dict[str, set[str]] = {}
        for pkg in packages:
            if pkg.kind == "port" and pkg.files:
                files.setdefault(pkg.instance_prefix, []).extend(pkg.files)
            elif pkg.kind == "formula":
                self.formulae.setdefault(pkg.instance_prefix, set()).add(pkg.name)
        self.files = {prefix: sorted(set(paths)) for prefix, paths in files.items()}
        self.cellar = {inst.prefix: system.identity(os.path.join(inst.prefix, "Cellar"))
                       for inst in instances if inst.manager is Manager.BREW}

    def known(self, inst: Instance) -> bool:
        """Return whether the ownership of an instance's files can be judged

        @param inst  an instance
        @returns     True for Homebrew, and for MacPorts whose packages are known, with a registry or the ports'
                     file lists
        """
        if inst.manager is Manager.BREW:
            return True
        return inst.inventory_known and (self.owner_of is not None or bool(self.files.get(inst.prefix)))

    def _registered(self, prefix: str, path: str) -> bool:
        """Return whether a port registered a path

        @param prefix  the MacPorts instance's prefix
        @param path    an absolute path in that prefix
        @returns       True when the registry names an owner, or the ports' `files` list the path or a file below it
        """
        if self.owner_of is not None:
            try:
                if self.owner_of(path):
                    return True
            except sqlite3.Error:      # a registry that cannot be queried registers nothing
                pass
        files = self.files.get(prefix, [])
        at = bisect.bisect_left(files, path)
        return at < len(files) and (files[at] == path or files[at].startswith(path.rstrip("/") + "/"))

    def owned(self, inst: Instance, paths: Sequence[str]) -> bool:
        """Return whether the instance's manager owns an entry

        @param inst   the instance whose prefix holds the entry
        @param paths  the entry first, then files inside or beside it that a package would register
        @returns      True when Homebrew's entry resolves into the Cellar, or a port registered any of the paths
        """
        if inst.manager is Manager.BREW:
            ident = self.cellar.get(inst.prefix)
            return ident is not None and system.lies_under(paths[0], ident)
        return any(self._registered(inst.prefix, p) for p in paths)

    def python_formula_owns(self, inst: Instance, version: str, name: str) -> bool:
        """Return whether an installed `python@<version>` put a distribution into the Homebrew prefix's site-packages

        Its install, or for 3.11 and older its post-install bootstrap, puts `BREW_PYTHON_DISTS` there.

        @param inst     the instance whose prefix holds the site-packages
        @param version  the Python version, such as `3.13`
        @param name     the distribution's name
        @returns        True for one of them while the formula is installed
        """
        if inst.manager is not Manager.BREW or f"python@{version}" not in self.formulae.get(inst.prefix, set()):
            return False
        major, minor = (int(part) for part in version.split(".")[:2])
        names = BREW_PYTHON_DISTS + (("setuptools",) if (major, minor) < (3, 12) else ())
        return name.lower() in names


def _metadata(dist_info: str) -> tuple[str, str | None]:
    """Return the name and version from `METADATA`, else from the directory name `<name>-<version>.dist-info`

    @param dist_info  a `*.dist-info` directory
    @returns          the name and the version; None for a version that neither gives
    """
    name: str | None = None
    version: str | None = None
    try:
        with open(os.path.join(dist_info, "METADATA"), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    break
                key, _, value = line.partition(":")
                if key == "Name" and name is None:
                    name = value.strip()
                elif key == "Version" and version is None:
                    version = value.strip()
    except OSError:
        pass
    stem = os.path.basename(dist_info)[:-len(".dist-info")]
    fallback_name, _, fallback_version = stem.partition("-")
    return name or fallback_name, version or (fallback_version or None)


def _record_outside(dist_info: str, site: str) -> list[str]:
    """Return the files `RECORD` lists outside site-packages, such as the console scripts in `bin`

    @param dist_info  a `*.dist-info` directory
    @param site       the site-packages directory that holds it
    @returns          the paths that are present; empty when `RECORD` cannot be read
    """
    out: list[str] = []
    try:
        with open(os.path.join(dist_info, "RECORD"), encoding="utf-8", errors="replace", newline="") as fh:
            rows = list(csv.reader(fh))
    except (OSError, csv.Error):
        return out
    for row in rows:
        if not row or not row[0]:
            continue
        full = os.path.normpath(os.path.join(site, row[0]))
        if not full.startswith(site.rstrip("/") + "/") and os.path.lexists(full):
            out.append(full)
    return out


def _dists(site: str) -> list[dict[str, Any]]:
    """Return the distributions installed in a site-packages directory

    @param site  a site-packages directory
    @returns     the `name`, `version` and `path` of each `*.dist-info` directory
    """
    out = []
    for path in _glob(site, "*.dist-info"):
        if os.path.isdir(path):
            name, version = _metadata(path)
            out.append({"name": name, "version": version, "path": path})
    return out


def _brew_pythons(inst: Instance) -> dict[str, str]:
    """Map every 3.X of a Homebrew instance to its `<prefix>/lib/python3.X/site-packages`

    @param inst  a Homebrew instance
    @returns     the site-packages directory by version, for each one present and each `bin/python3.X`
    """
    out: dict[str, str] = {}
    for site in _glob(inst.prefix, "lib", "python3.*", "site-packages"):
        m = _PY_SITE.search(os.path.dirname(site))
        if m:
            out[m.group(1)] = site
    for exe in _glob(inst.prefix, "bin", "python3.*"):
        m = _PY_EXE.match(os.path.basename(exe))
        if m:
            out.setdefault(m.group(1), os.path.join(inst.prefix, "lib", "python" + m.group(1), "site-packages"))
    return out


def _ports_pythons(inst: Instance) -> dict[str, str]:
    """Map every 3.X of a MacPorts instance to its framework's `Versions/3.X/lib/python3.X/site-packages`

    @param inst  a MacPorts instance
    @returns     the site-packages directory by version, for each framework version and each `bin/python3.X`
    """
    out: dict[str, str] = {}
    framework = os.path.join(inst.prefix, "Library", "Frameworks", "Python.framework", "Versions")
    for version_dir in _glob(framework, "3.*"):
        version = os.path.basename(version_dir)
        if _VERSION_DIR.match(version):
            out[version] = os.path.join(version_dir, "lib", "python" + version, "site-packages")
    for exe in _glob(inst.prefix, "bin", "python3.*"):
        m = _PY_EXE.match(os.path.basename(exe))
        if m:
            v = m.group(1)
            out.setdefault(v, os.path.join(framework, v, "lib", "python" + v, "site-packages"))
    return out


def _python(instances: Sequence[Instance], owners: _Ownership, home: str, *, frameworks: Sequence[str],
            attributed: list[str], notes: list[str]) -> list[dict[str, Any]]:
    """List the unowned `*.dist-info` per prefix, then the framework user site of every 3.X a manager provides

    `~/.local/lib/python3.X` belongs to non-framework interpreters and is never attributed.

    @param instances   the instances
    @param owners      the ownership of the instances' files
    @param home        the user's home
    @param frameworks  the `Versions` directories of the Python frameworks that may share a user site
    @param attributed  receives the `RECORD` scripts of the listed prefix dists
    @param notes       receives a note for each site-packages whose ownership is unknown
    @returns           one entry per prefix site-packages with unowned dists and per user site with dists or scripts
    """
    out: list[dict[str, Any]] = []
    providers: dict[str, list[str]] = {}
    for inst in instances:
        pythons = _brew_pythons(inst) if inst.manager is Manager.BREW else _ports_pythons(inst)
        for version, site in sorted(pythons.items()):
            providers.setdefault(version, []).append(inst.prefix)
            if not owners.known(inst):
                notes.append(f"ownership of {site} is unknown: its site-packages are not listed")
                continue
            dists = [d for d in _dists(site)
                     if not owners.owned(inst, [d["path"], os.path.join(d["path"], "METADATA"),
                                                os.path.join(d["path"], "RECORD")])
                     and not owners.python_formula_owns(inst, version, d["name"])]
            scripts = sorted({p for d in dists for p in _record_outside(d["path"], site)})
            attributed.extend(scripts)
            if dists:
                out.append({"version": version, "instance_prefix": inst.prefix, "location": "prefix",
                            "site_packages": site, "dists": dists, "scripts": scripts})
    for version in sorted(providers):
        base = os.path.join(home, "Library", "Python", version)
        site = os.path.join(base, "lib", "python", "site-packages")
        dists = _dists(site)
        scripts = [p for p in _glob(base, "bin", "*") if os.path.isfile(p)]
        if dists or scripts:
            out.append({"version": version, "instance_prefix": None, "location": "user", "site_packages": site,
                        "dists": dists, "scripts": scripts, "instances": providers[version],
                        "shared_with": [os.path.join(f, version) for f in frameworks
                                        if os.path.isdir(os.path.join(f, version))]})
    return out


def _pipx(index: PrefixIndex, home: str) -> list[dict[str, Any]]:
    """List the pipx venvs whose `pyvenv.cfg` `home =` line points into a manager's prefix

    @param index  the instances, by the paths they own
    @param home   the user's home
    @returns      the `venv`, `name`, `version`, Python `home` and `instance_prefix` of each such venv
    """
    out = []
    for rel in PIPX_HOMES:
        for venv in _glob(os.path.join(home, rel), "*"):
            python_home = None
            try:
                with open(os.path.join(venv, "pyvenv.cfg"), encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        key, _, value = line.partition("=")
                        if key.strip() == "home":
                            python_home = value.strip()
                            break
            except OSError:
                continue
            inst = index.owner(python_home) if python_home else None
            if inst is None:
                continue
            name, version = os.path.basename(venv), None
            try:
                with open(os.path.join(venv, "pipx_metadata.json"), encoding="utf-8") as fh:
                    main = json.load(fh).get("main_package") or {}
                name = main.get("package") or name
                version = main.get("package_version") or None
            except (OSError, ValueError, AttributeError):
                pass
            out.append({"venv": venv, "name": name, "version": version, "home": python_home,
                        "instance_prefix": inst.prefix})
    return out


def _package_json_version(directory: str) -> str | None:
    """Return the version an npm package's `package.json` gives

    @param directory  the package's directory
    @returns          the version; None when the file is unreadable or gives no text version
    """
    try:
        with open(os.path.join(directory, "package.json"), encoding="utf-8") as fh:
            value = json.load(fh).get("version")
    except (OSError, ValueError, AttributeError):
        return None
    return value if isinstance(value, str) else None


def _node_modules(root: str) -> list[tuple[str, str]]:
    """List the packages `<root>/<name>` and `<root>/@<scope>/<name>` of a `node_modules` directory

    @param root  the `node_modules` directory
    @returns     the name and directory of each package; a scoped name keeps its `@<scope>/` part
    """
    out = []
    for path in _glob(root, "*"):
        base = os.path.basename(path)
        if base.startswith("@"):
            for sub in _glob(path, "*"):
                if os.path.isdir(sub):
                    out.append((base + "/" + os.path.basename(sub), sub))
        elif os.path.isdir(path) and not base.startswith("."):
            out.append((base, path))
    return out


def _npm(instances: Sequence[Instance], owners: _Ownership, home: str, attributed: list[str]) -> list[dict[str, Any]]:
    """List the unowned npm globals of each prefix, and those in the user's `~/.npm-global`

    @param instances   the instances; one whose ownership is unknown is skipped
    @param owners      the ownership of the instances' files
    @param home        the user's home
    @param attributed  receives the `bin` links into the unowned packages
    @returns           the `instance_prefix` (None for the user's), `name`, `version` and `path` of each package
    """
    out = []
    for inst in instances:
        if not owners.known(inst):
            continue
        unowned_dirs = []
        for name, path in _node_modules(os.path.join(inst.prefix, "lib", "node_modules")):
            if owners.owned(inst, [path, os.path.join(path, "package.json")]):
                continue
            unowned_dirs.append(os.path.realpath(path))
            out.append({"instance_prefix": inst.prefix, "name": name, "version": _package_json_version(path),
                        "path": path})
        for link in _glob(inst.prefix, "bin", "*"):
            real = os.path.realpath(link)
            if os.path.islink(link) and any(real.startswith(d + "/") for d in unowned_dirs):
                attributed.append(link)
    for name, path in _node_modules(os.path.join(home, ".npm-global", "lib", "node_modules")):
        out.append({"instance_prefix": None, "name": name, "version": _package_json_version(path), "path": path})
    return out


def _gem_entry(inst: Instance | None, gem_dir: str) -> dict[str, Any]:
    """Return the entry of one gem, read from its directory name `<name>-<version>-<platform>`

    @param inst     the instance that holds the gem; None for the user's
    @param gem_dir  the gem's directory; its platform part is optional
    @returns        the `instance_prefix`, `name`, `version`, `platform` and `path`; an odd name is kept whole
    """
    m = _GEM_DIR.match(os.path.basename(gem_dir))
    name, version, platform = (m.group("name"), m.group("version"), m.group("platform")) if m else (
        os.path.basename(gem_dir), None, None)
    return {"instance_prefix": inst.prefix if inst else None, "name": name, "version": version,
            "platform": platform, "path": gem_dir}


def _gems(instances: Sequence[Instance], owners: _Ownership, home: str, attributed: list[str]) -> list[dict[str, Any]]:
    """List the unowned gems of each prefix, and the user's

    Homebrew keeps them in `lib/ruby/gems/*/gems/*`, MacPorts in `lib/ruby3.X/gems/*/gems/*`, the user in
    `~/.gem/ruby/*/gems/*`.

    @param instances   the instances; one whose ownership is unknown is skipped
    @param owners      the ownership of the instances' files
    @param home        the user's home
    @param attributed  receives the `bin` wrappers of the unowned gems' executables
    @returns           one entry per gem, as `_gem_entry` builds it
    """
    out = []
    for inst in instances:
        if not owners.known(inst):
            continue
        pattern = ("lib", "ruby", "gems", "*", "gems", "*") if inst.manager is Manager.BREW else (
            "lib", "ruby3.*", "gems", "*", "gems", "*")
        for gem_dir in _glob(inst.prefix, *pattern):
            if not os.path.isdir(gem_dir):
                continue
            root = os.path.dirname(os.path.dirname(gem_dir))
            spec = os.path.join(root, "specifications", os.path.basename(gem_dir) + ".gemspec")
            if owners.owned(inst, [gem_dir, spec]):
                continue
            out.append(_gem_entry(inst, gem_dir))
            for exe_dir in ("exe", "bin"):
                for exe in _glob(gem_dir, exe_dir, "*"):
                    for wrapper in (os.path.join(inst.prefix, "bin", os.path.basename(exe)),
                                    os.path.join(root, "bin", os.path.basename(exe))):
                        if os.path.isfile(wrapper) and wrapper not in attributed:
                            attributed.append(wrapper)
    for gem_dir in _glob(os.path.join(home, ".gem", "ruby"), "*", "gems", "*"):
        if os.path.isdir(gem_dir):
            out.append(_gem_entry(None, gem_dir))
    return out


def module_name(relative: str) -> str:
    """Return the module a path names: `5.40/darwin-thread-multi-2level/Foo/Bar.pm` -> `Foo::Bar`

    @param relative  a module's path below a `site_perl` or `lib/perl5` directory
    @returns         the module name, without a leading version or architecture directory
    """
    parts = relative.split("/")
    if parts and _VERSION_DIR.match(parts[0]):
        parts = parts[1:]
    if parts and ("-thread-multi" in parts[0] or parts[0].startswith("darwin")):
        parts = parts[1:]
    name = "::".join(parts)
    return name[:-3] if name.endswith(".pm") else name


def _cpan(instances: Sequence[Instance], owners: _Ownership, home: str) -> list[dict[str, Any]]:
    """List the unowned Perl modules under `lib/perl5/site_perl/**`, and those in `~/perl5/lib/perl5`

    @param instances  the instances; one whose ownership is unknown is skipped
    @param owners     the ownership of the instances' files
    @param home       the user's home
    @returns          the `instance_prefix` (None for the user's), `module` and `path` of each module
    """
    out: list[dict[str, Any]] = []
    for inst in instances:
        if not owners.known(inst):
            continue
        base = os.path.join(inst.prefix, "lib", "perl5", "site_perl")
        for path in _glob(base, "**"):
            if path.endswith(".pm") and os.path.isfile(path) and not owners.owned(inst, [path]):
                out.append({"instance_prefix": inst.prefix, "module": module_name(os.path.relpath(path, base)),
                            "path": path})
    base = os.path.join(home, "perl5", "lib", "perl5")
    for path in _glob(base, "**"):
        if path.endswith(".pm") and os.path.isfile(path):
            out.append({"instance_prefix": None, "module": module_name(os.path.relpath(path, base)), "path": path})
    return out


def extras(instances: Sequence[Instance], packages: Iterable[Package], home: str, *,
           owner_of: OwnerOf | None = None, frameworks: Sequence[str] = FRAMEWORKS) -> dict[str, Any]:
    """Scan the interpreter extras of every instance and of the user

    `attributed` lists their entry points in the prefixes (`RECORD` scripts, npm links, gem wrappers), never
    stray files; an instance of unknown ownership gets a note and no prefix-level entries.

    @param instances   the instances
    @param packages    the inventoried packages; the ports' `files` judge ownership where no registry names an owner
    @param home        the user's home
    @param owner_of    returns the port that registered a path; None when no registry is read
    @param frameworks  the `Versions` directories of the Python frameworks that may share a user site
    @returns           the `python`, `pipx`, `npm`, `gems` and `cpan` entries, the `notes` and the `attributed` paths
    """
    instances = list(instances)
    owners = _Ownership(instances, packages, owner_of)
    attributed: list[str] = []
    notes: list[str] = []
    for inst in instances:
        if not owners.known(inst):
            notes.append(f"MacPorts ownership unknown for {inst.prefix}: its prefix-level extras are not listed")
    result = {
        "python": _python(instances, owners, home, frameworks=frameworks, attributed=attributed, notes=notes),
        "pipx": _pipx(PrefixIndex(instances), home),
        "npm": _npm(instances, owners, home, attributed),
        "gems": _gems(instances, owners, home, attributed),
        "cpan": _cpan(instances, owners, home),
        "notes": sorted(set(notes)),
    }
    result["attributed"] = sorted(set(attributed))
    return result


# Requirements files ------------------------------------------------------------------

def _grouped(items: Iterable[dict[str, Any]], line: Callable[[dict[str, Any]], str]) -> list[str]:
    """Return the lines of a requirements file, under one `# <prefix>` heading per instance and `# user`

    @param items  the entries of one kind
    @param line   returns an entry's requirements line
    @returns      each heading, in sorted order, followed by the lines of its entries
    """
    groups: dict[str, list[str]] = {}
    for item in items:
        groups.setdefault(item.get("instance_prefix") or "user", []).append(line(item))
    out: list[str] = []
    for where in sorted(groups):
        out.append(f"# {where}")
        out.extend(groups[where])
    return out


def requirements(result: dict[str, Any]) -> dict[str, str]:
    """Return the text of each requirements file that has entries, by file name

    The files are `requirements-python3.X.txt`, `pipx-venvs.txt`, `npm-globals.txt`, `gems.txt` and
    `cpan-modules.txt`.

    @param result  the interpreter extras, as `extras` returns them
    @returns       the texts by file name, each ending in a newline
    """
    files: dict[str, list[str]] = {}
    for item in result.get("python") or []:
        if not item.get("dists"):
            continue
        lines = files.setdefault(f"requirements-python{item['version']}.txt", [])
        lines.append(f"# {item.get('instance_prefix') or 'user site'}: {item['site_packages']}")
        for dist in item["dists"]:
            lines.append(f"{dist['name']}=={dist['version']}" if dist.get("version") else dist["name"])
    if result.get("pipx"):
        files["pipx-venvs.txt"] = _grouped(result["pipx"], lambda i: (
            f"{i['name']}=={i['version']}" if i.get("version") else i["name"]) + f"  # python {i['home']}")
    if result.get("npm"):
        files["npm-globals.txt"] = _grouped(result["npm"], lambda i: (
            f"{i['name']}@{i['version']}" if i.get("version") else i["name"]))
    if result.get("gems"):
        files["gems.txt"] = _grouped(result["gems"], lambda i: (
            f"{i['name']} ({i['version']})" if i.get("version") else i["name"]))
    if result.get("cpan"):
        files["cpan-modules.txt"] = _grouped(result["cpan"], lambda i: i["module"])
    return {name: "\n".join(lines) + "\n" for name, lines in files.items()}


def write_requirements(directory: str, result: dict[str, Any]) -> list[str]:
    """Write the requirements files into the run directory

    @param directory  the run directory, made when missing
    @param result     the interpreter extras, as `extras` returns them
    @returns          the paths written, in file name order
    """
    os.makedirs(directory, exist_ok=True)
    paths = []
    for name, content in sorted(requirements(result).items()):
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        paths.append(path)
    return paths

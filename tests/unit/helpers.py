"""Builders shared by the unit tests"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from typing import Any

from brew_ports import model, state


def write_file(path: str, text: str = "", mode: int | None = None) -> str:
    """Write a text file, making its directory first

    @param path  the file
    @param text  its content
    @param mode  its permission bits; None leaves the default
    @returns     the path
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    if mode is not None:
        os.chmod(path, mode)
    return path


def make_instance(manager: model.Manager = model.Manager.BREW, prefix: str = "/opt/homebrew",
                  **kw: Any) -> model.Instance:
    """Return a usable, drivable instance

    @param manager  the instance's package manager
    @param prefix   the instance's prefix
    @param kw       `Instance` fields that override the defaults
    @returns        the instance
    """
    defaults: dict[str, Any] = {
        "manager": manager, "prefix": prefix, "identity": (1, 2), "spellings": (prefix,),
        "binary": prefix + ("/bin/brew" if manager is model.Manager.BREW else "/bin/port"),
        "version": "7.0.11" if manager is model.Manager.BREW else "2.12.7", "arch": "arm64",
        "usability": model.Usability.USABLE, "usability_detail": None, "drivable": True, "inventory_error": None,
        "repository": prefix if manager is model.Manager.BREW else None, "cache_dir": None,
        "portdbpath": None if manager is model.Manager.BREW else prefix + "/var/macports",
        "applications_dir": None if manager is model.Manager.BREW else "/Applications/MacPorts",
        "owned_roots": (prefix,),
    }
    defaults.update(kw)
    return model.Instance(**defaults)


def make_package(name: str = "wget", kind: str = "formula", prefix: str = "/opt/homebrew", **kw: Any) -> model.Package:
    """Return a requested, active package

    @param name    the package name
    @param kind    formula, cask or port
    @param prefix  the prefix of the instance that holds it
    @param kw      `Package` fields that override the defaults
    @returns       the package
    """
    defaults: dict[str, Any] = {
        "instance_prefix": prefix, "kind": kind, "name": name, "version": "1.0", "epoch": 0, "spec_args": [name],
        "requested": True, "requested_variants": [], "active": True, "linked": True, "keg_only": False,
        "pinned": False, "outdated": False, "deprecated": False, "disabled": False, "catalogue_present": True,
        "renamed_to": None, "origin": "homebrew/core", "homepage": None, "description": None, "deps": [],
        "cask_deps": [], "dependents": [], "executables": [], "privileged_install": False,
        "privileged_uninstall": False, "auto_updates": False, "caskroom_data": [], "built_locally": False,
        "built_on_os": None, "archs": ["arm64"], "services": [], "select_groups": [], "receipt_ok": True,
    }
    defaults.update(kw)
    return model.Package(**defaults)


class TempDirTest(unittest.TestCase):
    """A test case with a private temporary directory, removed when the test ends"""

    def setUp(self) -> None:
        super().setUp()
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="bp-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def path(self, *parts: str) -> str:
        """Return a path inside the temporary directory

        @param parts  the path's components below the directory
        @returns      the joined path
        """
        return os.path.join(self.tmp, *parts)

    def write(self, rel: str, text: str = "") -> str:
        """Write a text file inside the temporary directory, making its parent directories

        @param rel   the file's path below the directory
        @param text  the file's content
        @returns     the file's full path
        """
        full = self.path(rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(text)
        return full

    def state_dir(self) -> state.StateDir:
        """Return a state directory at `state` inside the temporary directory, not yet created

        @returns  the state directory
        """
        return state.StateDir(self.path("state"))

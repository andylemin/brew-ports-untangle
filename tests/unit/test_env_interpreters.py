"""Interpreter extras: pip, the framework user site, pipx, npm, gems, cpan"""

import json
import os
import unittest

from brew_ports import model
from brew_ports.env import interpreters as ip
from tests.unit.helpers import make_package
from tests.unit.test_env_paths import EnvTest


class InterpretersTest(EnvTest):
    """The base of the interpreter extras tests: a home, a Homebrew and a MacPorts instance, and a framework"""

    def setUp(self):
        super().setUp()
        self.home = self.path("Users", "alice")
        os.makedirs(self.home)
        self.brew = self.instance(model.Manager.BREW, "opt/homebrew")
        self.ports = self.instance(model.Manager.PORTS, "opt/local")
        self.brew_prefix, self.ports_prefix = self.brew.prefix, self.ports.prefix
        self.fw = self.path("frameworks")        # stands in for the CLT and python.org frameworks

    def dist(self, site, name, version, record=()):
        """Write a `*.dist-info` directory with its `METADATA`, and its `RECORD` when files are given

        @param site     the site-packages directory
        @param name     the distribution's name
        @param version  its version
        @param record   the paths `RECORD` lists, relative to the site
        @returns        the `*.dist-info` directory
        """
        path = os.path.join(site, f"{name.replace('-', '_')}-{version}.dist-info")
        meta = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nName: not-a-header\n"
        self.touch(os.path.join(path, "METADATA"), meta.encode())
        if record:
            self.touch(os.path.join(path, "RECORD"), "".join(f"{rel},sha256=x,1\n" for rel in record).encode())
        return path

    def extras(self, packages=(), owner_of=None):
        """Scan the interpreter extras of both instances, with the stand-in framework

        @param packages  the inventoried packages
        @param owner_of  returns the port that registered a path; None when no registry is read
        @returns         the extras, as `ip.extras` returns them
        """
        return ip.extras([self.brew, self.ports], list(packages), self.home, owner_of=owner_of, frameworks=(self.fw,))


class PythonTest(InterpretersTest):
    """Tests of the Python extras: the prefixes' site-packages, the framework user site and their ownership"""

    def test_the_framework_user_site(self):
        os.makedirs(os.path.join(self.brew_prefix, "lib", "python3.12", "site-packages"))
        user = os.path.join(self.home, "Library", "Python", "3.12")
        self.dist(os.path.join(user, "lib", "python", "site-packages"), "requests", "2.32.0")
        script = self.touch(os.path.join(user, "bin", "normalizer"), b"#!python\n", 0o755)
        self.dist(os.path.join(self.home, ".local", "lib", "python3.12", "site-packages"), "pyenv-only", "1.0")
        self.dist(os.path.join(self.home, "Library", "Python", "3.11", "lib", "python", "site-packages"), "old", "1.0")
        os.makedirs(os.path.join(self.fw, "3.12"))
        result = self.extras(owner_of=lambda path: None)
        [item] = [i for i in result["python"] if i["location"] == "user"]
        self.assertEqual((item["version"], item["instances"], item["scripts"], item["shared_with"]),
                         ("3.12", [self.brew_prefix], [script], [os.path.join(self.fw, "3.12")]))
        self.assertEqual([(d["name"], d["version"]) for d in item["dists"]], [("requests", "2.32.0")])
        self.assertNotIn("pyenv-only", json.dumps(result))
        self.assertNotIn("old-1.0", json.dumps(result))

    def test_homebrew_site_packages_outside_every_keg(self):
        site = os.path.join(self.brew_prefix, "lib", "python3.12", "site-packages")
        keg = self.dist(os.path.join(self.brew_prefix, "Cellar", "numpy", "2.0", "lib", "python3.12", "site-packages"),
                        "numpy", "2.0")
        os.makedirs(site)
        os.symlink(keg, os.path.join(site, "numpy-2.0.dist-info"))
        self.dist(site, "black", "24.1.0", record=["black/__init__.py", "../../../bin/black", "../../../bin/gone"])
        black = self.touch(os.path.join(self.brew_prefix, "bin", "black"), b"#!python\n", 0o755)
        result = self.extras(owner_of=lambda path: None)
        got = [(i["instance_prefix"], i["version"], [d["name"] for d in i["dists"]], i["scripts"])
               for i in result["python"] if i["location"] == "prefix"]
        self.assertEqual(got, [(self.brew_prefix, "3.12", ["black"], [black])])
        self.assertIn(black, result["attributed"])

    def test_the_python_formula_owns_its_prefix_site_packages(self):
        for version in ("3.11", "3.13"):
            site = os.path.join(self.brew_prefix, "lib", f"python{version}", "site-packages")
            for name in ("pip", "wheel", "setuptools", "requests"):
                self.dist(site, name, "1.0")
        formulae = [make_package(f"python@{v}", prefix=self.brew_prefix) for v in ("3.11", "3.13")]

        def listed(packages):
            result = self.extras(packages, owner_of=lambda path: None)
            return {i["version"]: [d["name"] for d in i["dists"]] for i in result["python"]
                    if i["instance_prefix"] == self.brew_prefix}
        self.assertEqual(listed(formulae), {"3.11": ["requests"], "3.13": ["requests", "setuptools"]})
        self.assertEqual(listed(formulae[1:])["3.11"], ["pip", "requests", "setuptools", "wheel"])

    def test_macports_site_packages_not_in_files(self):
        site = os.path.join(self.ports_prefix, "Library", "Frameworks", "Python.framework", "Versions", "3.13", "lib",
                            "python3.13", "site-packages")
        six = self.dist(site, "six", "1.16.0")
        self.dist(site, "httpx", "0.27.0")
        registered = {os.path.join(six, "METADATA"): "py313-six"}

        def names(result):
            return [d["name"] for i in result["python"] if i["instance_prefix"] == self.ports_prefix
                    for d in i["dists"]]
        self.assertEqual(names(self.extras(owner_of=registered.get)), ["httpx"])
        port = make_package("py313-six", kind="port", prefix=self.ports_prefix,
                            files=[os.path.join(six, "METADATA"), os.path.join(six, "RECORD")])
        self.assertEqual(names(self.extras([port])), ["httpx"])
        unknown = self.extras()
        self.assertEqual(names(unknown), [])
        self.assertTrue(any(self.ports_prefix in note for note in unknown["notes"]))
        self.ports.inventory_known = False      # the registry backup failed, so no port is known
        unread = self.extras(owner_of=registered.get)
        self.assertEqual(names(unread), [])
        self.assertIn(f"MacPorts ownership unknown for {self.ports_prefix}: its prefix-level extras are not listed",
                      unread["notes"])


class OtherLanguagesTest(InterpretersTest):
    """Tests of the pipx venvs, npm globals, gems and cpan modules"""

    def test_pipx_venvs_on_a_manager_python(self):
        python_home = os.path.join(self.brew_prefix, "opt", "python@3.12", "bin")
        os.makedirs(python_home)
        venv = os.path.join(self.home, ".local", "pipx", "venvs", "black")
        self.touch(os.path.join(venv, "pyvenv.cfg"),
                   f"home = {python_home}\ninclude-system-site-packages = false\nversion = 3.12.7\n".encode())
        self.touch(os.path.join(venv, "pipx_metadata.json"),
                   json.dumps({"main_package": {"package": "black", "package_version": "24.10.0"}}).encode())
        ported = os.path.join(self.home, "Library", "Application Support", "pipx", "venvs", "tool")
        self.touch(os.path.join(ported, "pyvenv.cfg"), (f"home = {self.ports_prefix}/bin\n").encode())
        system = os.path.join(self.home, ".local", "pipx", "venvs", "httpie")
        self.touch(os.path.join(system, "pyvenv.cfg"), b"home = /usr/bin\n")
        os.makedirs(os.path.join(self.home, ".local", "pipx", "venvs", "no-cfg"))
        got = [(i["name"], i["version"], i["instance_prefix"]) for i in self.extras()["pipx"]]
        self.assertEqual(got, [("black", "24.10.0", self.brew_prefix), ("tool", None, self.ports_prefix)])

    def test_npm_globals_at_both_depths(self):
        modules = os.path.join(self.brew_prefix, "lib", "node_modules")
        keg_npm = os.path.join(self.brew_prefix, "Cellar", "node", "22.0", "lib", "node_modules", "npm")
        self.touch(os.path.join(keg_npm, "package.json"), b'{"version": "10.9.0"}')
        os.makedirs(modules)
        os.symlink(keg_npm, os.path.join(modules, "npm"))
        ts = os.path.join(modules, "typescript")
        self.touch(os.path.join(ts, "package.json"), b'{"name": "typescript", "version": "5.6.2"}')
        self.touch(os.path.join(ts, "bin", "tsc"), b"", 0o755)
        self.touch(os.path.join(modules, "@vue", "cli", "package.json"), b'{"version": "5.0.8"}')
        os.makedirs(os.path.join(self.brew_prefix, "bin"))
        os.symlink("../lib/node_modules/typescript/bin/tsc", os.path.join(self.brew_prefix, "bin", "tsc"))
        os.symlink(os.path.join(keg_npm, "bin", "npm-cli.js"), os.path.join(self.brew_prefix, "bin", "npm"))
        self.touch(os.path.join(self.ports_prefix, "lib", "node_modules", "npm", "package.json"),
                   b'{"version": "10.8.0"}')
        os.makedirs(os.path.join(self.ports_prefix, "lib", "node_modules", "yarn"))
        self.touch(os.path.join(self.home, ".npm-global", "lib", "node_modules", "prettier", "package.json"),
                   b'{"version": "3.3.3"}')
        registered = {os.path.join(self.ports_prefix, "lib", "node_modules", "npm", "package.json"): "npm10"}
        result = self.extras(owner_of=registered.get)
        self.assertEqual([(i["instance_prefix"], i["name"], i["version"]) for i in result["npm"]], [
            (self.brew_prefix, "@vue/cli", "5.0.8"), (self.brew_prefix, "typescript", "5.6.2"),
            (self.ports_prefix, "yarn", None), (None, "prettier", "3.3.3")])
        self.assertIn(os.path.join(self.brew_prefix, "bin", "tsc"), result["attributed"])
        self.assertNotIn(os.path.join(self.brew_prefix, "bin", "npm"), result["attributed"])

    def test_gems_and_cpan_modules(self):
        gems = os.path.join(self.brew_prefix, "lib", "ruby", "gems", "3.4.0")
        self.touch(os.path.join(gems, "gems", "rails-8.0.0", "exe", "rails"), b"")
        os.makedirs(os.path.join(gems, "gems", "nokogiri-1.16.0-arm64-darwin"))
        keg_gem = os.path.join(self.brew_prefix, "Cellar", "ruby", "3.4.1", "lib", "ruby", "gems", "3.4.0", "gems",
                               "rake-13.2.1")
        os.makedirs(keg_gem)
        os.symlink(keg_gem, os.path.join(gems, "gems", "rake-13.2.1"))
        wrapper = self.touch(os.path.join(gems, "bin", "rails"), b"#!ruby\n", 0o755)
        ports_gems = os.path.join(self.ports_prefix, "lib", "ruby3.3", "gems", "3.3.0")
        os.makedirs(os.path.join(ports_gems, "gems", "bundler-2.5.0"))
        os.makedirs(os.path.join(ports_gems, "gems", "sinatra-4.0.0"))
        spec = os.path.join(ports_gems, "specifications", "bundler-2.5.0.gemspec")
        os.makedirs(os.path.join(self.home, ".gem", "ruby", "3.3.0", "gems", "rubocop-1.66.0"))
        site = os.path.join(self.brew_prefix, "lib", "perl5", "site_perl")
        self.touch(os.path.join(site, "5.40", "darwin-thread-multi-2level", "Foo", "Bar.pm"), b"1;\n")
        keg_pm = self.touch(os.path.join(self.brew_prefix, "Cellar", "perl", "5.40", "lib", "Owned.pm"), b"1;\n")
        os.symlink(keg_pm, os.path.join(site, "5.40", "Owned.pm"))
        self.touch(os.path.join(self.home, "perl5", "lib", "perl5", "Local", "Mod.pm"), b"1;\n")
        result = self.extras(owner_of={spec: "rb33-bundler"}.get)
        self.assertEqual([(i["instance_prefix"], i["name"], i["version"], i["platform"]) for i in result["gems"]], [
            (self.brew_prefix, "nokogiri", "1.16.0", "arm64-darwin"), (self.brew_prefix, "rails", "8.0.0", None),
            (self.ports_prefix, "sinatra", "4.0.0", None), (None, "rubocop", "1.66.0", None)])
        self.assertIn(wrapper, result["attributed"])
        self.assertEqual([(i["instance_prefix"], i["module"]) for i in result["cpan"]],
                         [(self.brew_prefix, "Foo::Bar"), (None, "Local::Mod")])
        self.assertEqual(ip.module_name("Plain.pm"), "Plain")


class RequirementsTest(InterpretersTest):
    """Tests of the requirements files the extras give"""

    def result(self):
        """Return interpreter extras of every kind, an empty Python 3.13 site among them

        @returns  the extras, as `ip.extras` returns them
        """
        return {
            "python": [{"version": "3.12", "instance_prefix": self.brew_prefix, "site_packages": "/s",
                        "dists": [{"name": "black", "version": "24.1.0"}]},
                       {"version": "3.12", "instance_prefix": None, "site_packages": "/u",
                        "dists": [{"name": "requests", "version": None}]},
                       {"version": "3.13", "instance_prefix": self.ports_prefix, "site_packages": "/p", "dists": []}],
            "pipx": [{"name": "black", "version": "24.10.0", "home": "/h", "instance_prefix": self.brew_prefix}],
            "npm": [{"instance_prefix": self.brew_prefix, "name": "typescript", "version": "5.6.2"},
                    {"instance_prefix": None, "name": "prettier", "version": None}],
            "gems": [{"instance_prefix": self.brew_prefix, "name": "rails", "version": "8.0.0"}],
            "cpan": [{"instance_prefix": None, "module": "Local::Mod"}],
        }

    def test_contents(self):
        files = ip.requirements(self.result())
        self.assertEqual(sorted(files), ["cpan-modules.txt", "gems.txt", "npm-globals.txt", "pipx-venvs.txt",
                                         "requirements-python3.12.txt"])
        self.assertEqual(files["requirements-python3.12.txt"],
                         f"# {self.brew_prefix}: /s\nblack==24.1.0\n# user site: /u\nrequests\n")
        self.assertEqual(files["npm-globals.txt"], f"# {self.brew_prefix}\ntypescript@5.6.2\n# user\nprettier\n")
        self.assertEqual(files["pipx-venvs.txt"], f"# {self.brew_prefix}\nblack==24.10.0  # python /h\n")
        self.assertEqual(files["gems.txt"], f"# {self.brew_prefix}\nrails (8.0.0)\n")
        self.assertEqual(files["cpan-modules.txt"], "# user\nLocal::Mod\n")
        self.assertEqual(ip.requirements({}), {})

    def test_written_into_the_run_directory(self):
        run = self.path("run", "20261112-000000-abcdef")
        paths = ip.write_requirements(run, self.result())
        self.assertEqual([os.path.basename(p) for p in paths], ["cpan-modules.txt", "gems.txt", "npm-globals.txt",
                                                               "pipx-venvs.txt", "requirements-python3.12.txt"])
        with open(os.path.join(run, "gems.txt"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), f"# {self.brew_prefix}\nrails (8.0.0)\n")


if __name__ == "__main__":
    unittest.main()

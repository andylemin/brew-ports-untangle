"""Phase 5 of `apply`: removal order, live expansion, the login shell, service stops and restarts, plists"""

import os
import types
import unittest
from unittest import mock

from brew_ports import exec_remove, executor, scan, state
from brew_ports.homebrew import inventory as brew_inventory
from tests.unit.fixtures.executor import builders as b
from tests.unit.fixtures.macports import builders as mb
from tests.unit.helpers import TempDirTest, make_package
from tests.unit.test_executor import ApplyTest


class OrderTest(unittest.TestCase):
    """The dependents-first order of a removal's retries"""

    def test_dependents_come_first(self):
        deps = {"wget": {"libidn2", "openssl@3"}, "libidn2": {"libunistring"}, "curl": {"openssl@3"}}
        order = exec_remove.dependents_first(["curl", "libidn2", "libunistring", "openssl@3", "wget"], deps)
        for dependent, dependency in (("wget", "libidn2"), ("libidn2", "libunistring"), ("curl", "openssl@3"),
                                      ("wget", "openssl@3")):
            self.assertLess(order.index(dependent), order.index(dependency))
        self.assertEqual(sorted(order), ["curl", "libidn2", "libunistring", "openssl@3", "wget"])

    def test_unrelated_packages_keep_their_order(self):
        self.assertEqual(exec_remove.dependents_first(["b", "a", "c"], {}), ["b", "a", "c"])

    def test_a_cycle_keeps_its_listed_order(self):
        cycle = {"x": {"y"}, "y": {"x"}, "top": {"y"}}
        self.assertEqual(exec_remove.dependents_first(["y", "x", "top"], cycle), ["top", "y", "x"])

    def test_dependencies_outside_the_set_do_not_count(self):
        self.assertEqual(exec_remove.dependents_first(["jq"], {"jq": {"oniguruma", "jq"}}), ["jq"])


class ExpandTest(TempDirTest):
    """The expansion of the removal set against the live Cellar, Caskroom and registry"""

    def stub(self, inst, pairs, kegs=None, rooms=None):
        """Return a stand-in for a run whose plan removes pairs from one source, with a scan without packages

        The scan holds a Homebrew inventory of the source only when `kegs` or `rooms` fills it.

        @param inst   the source instance
        @param pairs  its `(kind, name)` pairs of the removal set
        @param kegs   the kegs of each formula in the scan's Homebrew inventory; None for none
        @param rooms  the Caskroom entry of each cask in that inventory; None for none
        @returns      the stand-in
        """
        inv = brew_inventory.HomebrewInventory(instance_prefix=inst.prefix, kegs=kegs or {}, caskrooms=rooms or {})
        bundle = scan.ScanBundle(result=types.SimpleNamespace(packages=[]), brew=[(inst, None, inv)] if kegs or rooms
                                 else [])
        plan = types.SimpleNamespace(removal_set={inst.prefix: pairs})
        return types.SimpleNamespace(plan=plan, bundle=bundle, phase6_begun=lambda p: False,
                                     fresh_instance=lambda p: inst if p == inst.prefix else None)

    def expand_one(self, inst, pairs, kegs=None, rooms=None):
        """Return the one removal `expand` makes for a single source

        @param inst   the source instance
        @param pairs  its `(kind, name)` pairs of the removal set
        @param kegs   the kegs of each formula in the scan's Homebrew inventory; None for none
        @param rooms  the Caskroom entry of each cask in that inventory; None for none
        @returns      the removal
        """
        removals = exec_remove.expand(self.stub(inst, pairs, kegs, rooms))
        self.assertEqual(len(removals), 1)
        return removals[0]

    def test_brew_expansion_matches_kinds_and_skips_links(self):
        prefix = b.brew_prefix(self.tmp, "usr/local")
        b.keg(prefix, "foo", "1.0")
        b.keg(prefix, "bar", "2.0", deps=["foo"])
        b.caskroom(prefix, "bar", "9.0")
        os.symlink(os.path.join(prefix, "Cellar", "foo"), os.path.join(prefix, "Cellar", "oldfoo"))
        inst = b.brew(prefix)
        pairs = [("formula", "foo"), ("formula", "oldfoo"), ("cask", "bar"), ("formula", "bar"), ("cask", "gone")]
        removal = self.expand_one(inst, pairs)
        self.assertEqual((removal.formulae, removal.casks), (["foo", "bar"], ["bar"]))
        self.assertEqual(removal.formula_order, ["bar", "foo"])
        self.assertEqual(removal.keys(),
                         {(prefix, "formula", "foo"), (prefix, "formula", "bar"), (prefix, "cask", "bar")})

    def test_a_formula_in_a_rack_under_its_old_name(self):
        prefix = b.brew_prefix(self.tmp, "usr/local")
        kegs = {"newname": [b.keg(prefix, "oldname", "1.0")], "tool": [b.keg(prefix, "tool", "2.0", deps=["oldname"])]}
        removal = self.expand_one(b.brew(prefix), [("formula", "newname"), ("formula", "tool")], kegs)
        self.assertEqual((removal.formulae, removal.formula_order), (["oldname", "tool"], ["tool", "oldname"]))
        self.assertEqual(removal.items(), ["formula oldname", "formula tool"])
        self.assertEqual(removal.keys(), {(prefix, "formula", "newname"), (prefix, "formula", "tool")})

    def test_casks_in_caskroom_entries_under_old_tokens(self):
        prefix = b.brew_prefix(self.tmp, "usr/local")
        rooms = {"docker-desktop": b.caskroom(prefix, "docker", "4.40.0"), "newterm": b.caskroom(prefix, "oldterm")}
        removal = self.expand_one(b.brew(prefix), [("cask", "docker-desktop"), ("cask-adopted", "newterm")],
                                  rooms=rooms)
        self.assertEqual((removal.casks, removal.adopted), (["docker"], ["oldterm"]))
        self.assertEqual(removal.items(), ["cask-adopted oldterm", "cask docker"])
        self.assertEqual(removal.keys(), {(prefix, "cask", "docker-desktop"), (prefix, "cask", "newterm")})

    def python_removal(self):
        """Return the removal of python313 (spelled Python313), whose two versions differ in state, and py313-pip

        @returns  the removal
        """
        prefix = b.ports_prefix(self.tmp, "opt/local", rows=[
            mb.port(1, "python313", "3.13.1", state="imaged"), mb.port(2, "python313", "3.13.2"),
            mb.port(3, "py313-pip", "25.0"), mb.port(4, "zlib", "1.3.1")], deps=[(3, "Python313"), (2, "zlib")])
        return self.expand_one(b.ports(prefix), [("port", "Python313"), ("port", "py313-pip")])

    def test_every_version_of_a_port_in_every_state(self):
        removal = self.python_removal()
        self.assertEqual(removal.ports, [["py313-pip", "@25.0_0"], ["python313", "@3.13.1_0"],
                                         ["python313", "@3.13.2_0"]])
        self.assertEqual(removal.port_order, ["py313-pip", "python313"])

    def test_port_uninstall_names_every_version(self):
        run = types.SimpleNamespace(runner=types.SimpleNamespace(host_arch="arm64"), target=None)
        action = exec_remove.uninstall_actions(run, self.python_removal())[0]
        self.assertEqual(action.argv[-6:], ["py313-pip", "@25.0_0", "python313", "@3.13.1_0", "python313",
                                            "@3.13.2_0"])
        self.assertEqual(action.split_order, ["py313-pip", "python313"])
        self.assertTrue(action.sudo)

    def test_two_spellings_of_a_port_are_each_named(self):
        prefix = b.ports_prefix(self.tmp, "opt/local", rows=[mb.port(1, "Py313-Pip", "24.0", state="imaged"),
                                                             mb.port(2, "py313-pip", "25.0")])
        removal = self.expand_one(b.ports(prefix), [("port", "py313-pip")])
        self.assertEqual(removal.port_order, ["Py313-Pip", "py313-pip"])

    def test_unreadable_registry_stops_the_phase(self):
        inst = b.ports(b.ports_prefix(self.tmp, "opt/local"))
        os.unlink(b.registry_db(inst.prefix))
        inst.inventory_known = False
        with self.assertRaises(executor.Stop) as caught:
            exec_remove.expand(self.stub(inst, [("port", "jq")]))
        self.assertIn("nothing was removed", caught.exception.lines[0])


class RemovalTest(ApplyTest):
    """A package left behind, a service that does not stop, and a resumed uninstall"""

    def test_package_left_behind_restarts_services(self):
        self.scenario_brew()
        self.responder.keep = {"dnsmasq"}
        self.assertEqual(self.apply(), executor.EXIT_ACTION, self.out)
        self.assertIn("phase 5 left 1 package(s) installed:", self.out)
        self.assertIn(f"port dnsmasq @2.90_0 ({self.source.prefix})", self.out)
        uninstalls = self.responder.ran("port", "uninstall")
        self.assertEqual([u[3::2] for u in uninstalls], [["dnsmasq", "jq", "oniguruma"], ["dnsmasq"], ["jq"],
                                                          ["oniguruma"]])
        self.assertEqual([t[-2:] for t in self.responder.ran("port", "load")], [["load", "dnsmasq"]])
        self.assertTrue(os.path.exists(self.plist))
        self.assertEqual(b.port_names(self.source.prefix), ["dnsmasq"])
        self.assertNotIn((5, "5.complete"), self.results())
        self.assertIn("apply --resume", self.out)

    def test_stuck_service_keeps_every_package(self):
        self.scenario_brew()
        self.responder.stuck = {"org.macports.dnsmasq"}
        self.assertEqual(self.apply(), executor.EXIT_ACTION, self.out)
        self.assertIn("launchd still holds system/org.macports.dnsmasq after 30 s", self.out)
        self.assertIn("a service did not stop: nothing was removed", self.out)
        self.assertEqual(self.responder.ran("port", "uninstall"), [])
        self.assertEqual(b.port_names(self.source.prefix), ["dnsmasq", "jq", "oniguruma"])

    def test_resumed_uninstall_names_only_the_rest(self):
        self.scenario_brew()

        def interrupted(_tail):
            b.drop_port(self.source.prefix, "dnsmasq", "@2.90_0")
            b.drop_port(self.source.prefix, "jq", "@1.7.1_0")
            self.runners[-1].note_sigint()
            return b.runner_mod.FakeResponse(exit=1)
        self.responder.hooks["uninstall"] = interrupted
        self.assertEqual(self.apply(), executor.EXIT_ACTION)
        first = self.run_dir.run_id
        del self.responder.hooks["uninstall"]
        self.responder.log.clear()
        self.assertEqual(self.apply(resume=first), executor.EXIT_OK, self.out)
        self.assertEqual(self.responder.ran("port", "uninstall"), [[self.source.binary, "-N", "uninstall", "oniguruma",
                                                                    "@6.9.9_0"]])
        self.assertEqual(self.responder.ran("tmutil"), [])            # phase 1 is not taken again
        self.assertFalse(os.path.exists(self.plist))
        self.assertEqual(self.results()[(5, "5.complete")], "ok")

    def test_a_rack_under_an_old_name_is_uninstalled_by_that_name(self):
        target = b.brew_prefix(self.tmp, "opt/homebrew")
        source = b.brew_prefix(self.tmp, "usr/local")
        keg = b.keg(source, "oldname", "1.0")
        self.target, self.source = b.brew(target), b.brew(source)
        newname = make_package("newname", "formula", source)
        self.host.instances = [self.target, self.source]
        self.host.packages = [newname]
        self.host.kegs[source] = {"newname": [keg]}
        self.host.environment = {"files": [], "etc_paths": []}
        self.save_plan(b.plan(self.target, [self.source], mappings=[b.mapping(newname, "formula", "newname")],
                              removal={source: [("formula", "newname")]}))
        self.responder.keep = {"oldname"}
        self.assertEqual(self.apply(), executor.EXIT_ACTION, self.out)
        self.assertIn("phase 5 left 1 package(s) installed:", self.out)
        self.assertIn(f"formula oldname ({source})", self.out)
        self.responder.keep = set()
        self.assertEqual(self.apply(resume=self.run_dir.run_id), executor.EXIT_OK, self.out)
        self.assertEqual(self.responder.ran("brew", "uninstall")[-1][1:],
                         ["uninstall", "--formula", "--force", "oldname"])
        self.assertFalse(os.path.lexists(os.path.dirname(keg)))

    def test_a_caskroom_entry_under_an_old_token_is_uninstalled(self):
        target = b.brew_prefix(self.tmp, "opt/homebrew")
        source = b.brew_prefix(self.tmp, "usr/local")
        room = b.caskroom(source, "docker", "4.40.0")
        self.target, self.source = b.brew(target), b.brew(source)
        self.host.instances = [self.target, self.source]
        self.host.packages = [make_package("docker-desktop", "cask", source)]
        self.host.rooms[source] = {"docker-desktop": room}
        self.host.environment = {"files": [], "etc_paths": []}
        self.save_plan(b.plan(self.target, [self.source], removal={source: [("cask", "docker-desktop")]}))
        self.responder.keep = {"docker"}
        self.assertEqual(self.apply(), executor.EXIT_ACTION, self.out)
        self.assertIn("phase 5 left 1 package(s) installed:", self.out)
        self.assertIn(f"cask docker ({source})", self.out)
        self.responder.keep = set()
        self.assertEqual(self.apply(resume=self.run_dir.run_id), executor.EXIT_OK, self.out)
        self.assertEqual(self.responder.ran("brew", "uninstall")[-1][1:], ["uninstall", "--cask", "--force", "docker"])
        self.assertFalse(os.path.lexists(room))


class AdoptedRecordTest(ApplyTest):
    """The source's record of a cask the target adopted"""

    def test_adopted_record_is_dropped_not_uninstalled(self):
        target = b.brew_prefix(self.tmp, "opt/homebrew")
        source = b.brew_prefix(self.tmp, "usr/local")
        room = b.caskroom(source, "firefox", "130.0")
        os.makedirs(os.path.join(room, "130.0", "bin"))
        os.symlink(os.path.join(room, "130.0", "bin", "firefox"), os.path.join(source, "bin", "firefox"))
        b.caskroom(target, "firefox", "130.0")
        b.keg(source, "wget", "1.24.5")
        self.target, self.source = b.brew(target), b.brew(source)
        firefox, wget = make_package("firefox", "cask", source), make_package("wget", "formula", source)
        self.host.instances = [self.target, self.source]
        self.host.packages = [firefox, wget]
        self.host.environment = {"files": [], "etc_paths": []}
        self.save_plan(b.plan(self.target, [self.source],
                              mappings=[b.mapping(firefox, "cask", "firefox", version="130.0", adopt=True),
                                        b.mapping(wget, "formula", "wget")],
                              removal={source: [("cask-adopted", "firefox"), ("formula", "wget")]}))
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        commands = [tail for _, tail in self.responder.log if tail[0] == b.runner_mod.RM
                    or (tail[0] == self.source.binary and tail[1] == "uninstall")]
        self.assertEqual(commands[0], [b.runner_mod.RM, "-rf", os.path.join(source, "bin", "firefox"), room])
        self.assertEqual(commands[1][1:], ["uninstall", "--formula", "--force", "wget"])
        self.assertFalse([t for t in self.responder.ran("brew", "uninstall") if "--cask" in t])
        self.assertFalse(os.path.lexists(os.path.join(source, "bin", "firefox")))
        self.assertTrue(os.path.isdir(os.path.join(target, "Caskroom", "firefox")))

    def test_a_record_adopted_under_the_target_token_is_dropped(self):
        target = b.brew_prefix(self.tmp, "opt/homebrew")
        source = b.brew_prefix(self.tmp, "usr/local")
        room = b.caskroom(source, "docker", "4.40.0")
        self.target, self.source = b.brew(target), b.brew(source)
        docker = make_package("docker", "cask", source)
        self.host.instances = [self.target, self.source]
        self.host.packages = [docker]
        self.host.environment = {"files": [], "etc_paths": []}
        self.save_plan(b.plan(self.target, [self.source],
                              mappings=[b.mapping(docker, "cask", "docker-desktop", version="4.40.0", adopt=True)],
                              removal={source: [("cask-adopted", "docker")]}))
        self.assertEqual(self.apply(dry_run=True), executor.EXIT_OK, self.out)
        self.assertIn(f"5.adopted.docker: the target's Caskroom does not hold docker-desktop, so the record in "
                      f"{source} stays", self.out)
        b.caskroom(target, "docker-desktop", "4.40.0")
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        self.assertEqual(self.responder.ran("rm"), [[b.runner_mod.RM, "-rf", room]])
        self.assertFalse(os.path.lexists(room))
        self.assertTrue(os.path.isdir(os.path.join(target, "Caskroom", "docker-desktop")))

    def test_a_record_left_under_an_old_token_is_dropped(self):
        target = b.brew_prefix(self.tmp, "opt/homebrew")
        source = b.brew_prefix(self.tmp, "usr/local")
        room = b.caskroom(source, "docker", "4.40.0")
        b.caskroom(target, "docker-desktop", "4.40.0")
        self.target, self.source = b.brew(target), b.brew(source)
        docker = make_package("docker-desktop", "cask", source)
        self.host.instances = [self.target, self.source]
        self.host.packages = [docker]
        self.host.rooms[source] = {"docker-desktop": room}
        self.host.environment = {"files": [], "etc_paths": []}
        self.save_plan(b.plan(self.target, [self.source],
                              mappings=[b.mapping(docker, "cask", "docker-desktop", version="4.40.0", adopt=True)],
                              removal={source: [("cask-adopted", "docker-desktop")]}))
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        self.assertEqual(self.responder.ran("rm"), [[b.runner_mod.RM, "-rf", room]])
        self.assertFalse(os.path.lexists(room))


class LoginShellTest(ApplyTest):
    """The login shell's switch from a source's zsh to the target's"""

    new_shell: str          # the target's zsh, set by scenario_shell
    shells: str             # the test's /etc/shells, set by scenario_shell

    def scenario_shell(self, removed=True, executable=True):
        """Give scenario A a login shell, the source's zsh port, and a test `/etc/shells` that lists it

        @param removed     whether the plan removes the zsh port
        @param executable  whether the target has an executable zsh to switch to
        """
        self.scenario_brew()
        shell = os.path.join(self.source.prefix, "bin", "zsh")
        b.add_port(self.source.prefix, "zsh", "5.9")
        zsh = make_package("zsh", "port", self.source.prefix, executables=["zsh"])
        self.host.packages.append(zsh)
        self.host.owners[self.source.prefix] = {shell: "zsh"}
        self.host.environment.update({"login_shell": shell, "login_shell_realpath": shell,
                                      "login_shell_prefix": self.source.prefix})
        self.new_shell = os.path.join(self.target.prefix, "bin", "zsh")
        if executable:
            with open(self.new_shell, "w") as fh:
                fh.write("#!/bin/sh\n")
            os.chmod(self.new_shell, 0o755)
            # The container's /tmp is a noexec tmpfs, where access(X_OK) fails for every file.
            real = os.access
            patcher = mock.patch("os.access", side_effect=lambda path, mode, **kw: True if path == self.new_shell
                                 else real(path, mode, **kw))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.shells = self.write_shells()
        removal = {self.source.prefix: self.removal[self.source.prefix] + ([("port", "zsh")] if removed else [])}
        mappings = self.mappings + ([b.mapping(zsh, "formula", "zsh", version="5.9")] if removed else [])
        self.save_plan(b.plan(self.target, [self.source], mappings=mappings, removal=removal, phase3=[self.install]))

    def write_shells(self):
        """Write a test `/etc/shells` that lists the source's zsh, and point phase 5 at it

        @returns  the file's path
        """
        path = self.path("etc", "shells")
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as fh:
            fh.write(f"/bin/bash\n/bin/zsh\n{self.source.prefix}/bin/zsh\n")
        patcher = mock.patch("brew_ports.exec_remove.ETC_SHELLS", path)
        patcher.start()
        self.addCleanup(patcher.stop)
        return path

    def test_the_shell_is_switched_before_any_removal(self):
        self.scenario_shell()
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        with open(self.shells) as fh:
            self.assertEqual(fh.read().splitlines()[-1], self.new_shell)
        log = [tail for _, tail in self.responder.log]
        chsh = log.index(["/usr/bin/chsh", "-s", self.new_shell, "alice"])
        uninstall = next(i for i, tail in enumerate(log) if tail[0] == self.source.binary and "uninstall" in tail)
        self.assertLess(chsh, uninstall)
        sudo_chsh = [sudo for sudo, tail in self.responder.log if tail[0] == "/usr/bin/chsh"]
        self.assertEqual(sudo_chsh, [True])
        note, = [e for e in self.entry("5.shell") if e.get("kind") == "note"]
        self.assertEqual((note["from"], note["to"], note["user"]), (os.path.join(self.source.prefix, "bin", "zsh"),
                                                                    self.new_shell, "alice"))
        write_id = f"5.write.{state.slug(os.path.realpath(self.shells))}"
        write, = [e for e in self.entry(write_id) if "sha256" in e]
        self.assertEqual((len(write["sha256"]), write["root"]), (64, True))
        self.assertEqual(self.results()[(5, write_id)], "ok")
        self.assertEqual(self.results()[(5, "5.shell")], "ok")

    def test_missing_target_shell_stops_the_run(self):
        self.scenario_shell(executable=False)
        self.assertEqual(self.apply(), executor.EXIT_ACTION)
        self.assertIn(f"the target has no executable {self.new_shell} to switch to: nothing was removed", self.out)
        self.assertEqual(self.responder.ran("chsh"), [])
        self.assertEqual(self.responder.ran("port", "uninstall"), [])
        self.assertEqual(self.responder.ran("launchctl", "bootout"), [])

    def test_a_shell_whose_package_stays_is_left_alone(self):
        self.scenario_shell(removed=False)
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        self.assertEqual(self.responder.ran("chsh"), [])
        self.assertEqual(b.FakeRootFiles.writes, [])


class SelectionTest(unittest.TestCase):
    """The owned services phase 5 stops"""

    def test_cask_adopted_services_are_never_selected(self):
        svc = b.service("homebrew.mxcl.firefox", "/x.plist", "/usr/local", "firefox", "cask", scope="user")
        port = b.service("org.macports.jq", "/y.plist", "/opt/local", "JQ", "port")
        run = types.SimpleNamespace(
            bundle=types.SimpleNamespace(result=types.SimpleNamespace(services=[svc, port])),
            plan=types.SimpleNamespace(removal_set={"/usr/local": [("cask-adopted", "firefox")],
                                                    "/opt/local": [("port", "jq")]}),
            fresh_prefix=lambda p: p)
        self.assertEqual(exec_remove.selected_services(run), [port])


if __name__ == "__main__":
    unittest.main()

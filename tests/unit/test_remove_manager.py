"""Phase 6 for MacPorts: checks, archives, unregistered entries and the "no" that keeps a prefix

Also the macports user, a second instance, the receipt, a resumed phase, the safety rules and the parsers
phase 6 relies on.
"""

import os
import shutil
import unittest

from brew_ports import env, envclean, remove_manager as rm, runner as r, state, system
from brew_ports.model import Manager
from tests.unit.fixtures.macports.builders import make_registry, port
from tests.unit.fixtures.remove_manager import builders as b
from tests.unit.helpers import TempDirTest, make_instance

CONF = rm.MACPORTS_CONF


class MacPortsTest(TempDirTest):
    """The site, MacPorts sources and startup items of the MacPorts phase 6 tests, with a Homebrew target"""

    def setUp(self):
        super().setUp()
        self.site = b.Site(self.tmp)
        self.fake = self.site.fake
        self.target = self.site.target_homebrew()

    def source(self, **kw):
        """Make a MacPorts source as phase 5 leaves it

        Base's files and an empty live registry, data in `var/db` and `etc`, a log under `var/log`, the user's
        `~/.macports`, and the phase 1 registry backup that still records `wget`.

        @param kw  fields of the instance, as `Site.macports` takes them
        @returns   the instance
        """
        inst = self.site.macports(**kw)
        p = inst.prefix
        b.write(os.path.join(p, "var", "db", "app", "data.db"))
        b.write(os.path.join(p, "var", "log", "app.log"))
        b.write(os.path.join(p, "etc", "app.conf"))
        b.write(os.path.join(self.site.home, ".macports", "macports.conf"), "# the user's settings\n")
        self.site.phase1_registry(inst, [port(1, "wget", "1.25.0")],
                                  [(1, os.path.join(p, "bin", "wget"), None, 1, 1)])
        return inst

    def service(self, inst, label="org.macports.app", loaded=True):
        """Build a MacPorts startup item: a link in `/Library/LaunchDaemons` into the prefix

        @param inst    the MacPorts instance
        @param label   the item's label
        @param loaded  whether launchd runs it, as PID 4242
        @returns       the service
        """
        program = os.path.join(inst.prefix, "bin", "appd")
        real = b.write_plist(os.path.join(inst.prefix, "etc", "LaunchDaemons", label, label + ".plist"), label, program)
        plist = b.link(real, os.path.join(self.site.library, "LaunchDaemons", label + ".plist"))
        if loaded:
            self.fake.jobs[("system", label)] = [b.printed("system", label, plist, program, pid=4242)]
        return b.service(label, plist, inst.prefix, "app", kind="port", scope="system",
                         domain="system" if loaded else None, loaded=loaded, pid=4242 if loaded else None,
                         program=program)

    def run_phase(self, inst, services=(), ask=None, *, others=(), resumed=False, target=None, **plan_kw):
        """Run phase 6 over a plan that names `inst`, beside the target and `others`

        @param inst      the MacPorts instance the plan removes
        @param services  the services of the scan bundle
        @param ask       answers the prompts; None answers yes
        @param others    further instances on the host
        @param resumed   read this run's earlier phase 6 records
        @param target    the plan's target; None for the test's own
        @param plan_kw   further fields of the plan
        @returns         the report lines
        """
        target = target or self.target
        instances = [target, inst] + list(others)
        plan = self.site.plan(target, instances, [inst], **plan_kw)
        return self.site.run(plan, self.site.bundle(instances, services), ask, resumed=resumed)

    def deletes(self, program, word):
        """Return the command lines of a program that hold a word

        @param program  the program's path
        @param word     a word such as `-delete` or `--forget`
        @returns        the command lines, in order
        """
        return [argv for _, argv in self.fake.ran(program) if word in argv]


class RemovalTest(MacPortsTest):
    """The checks, archives and deletions of a MacPorts removal, and what stops them"""

    def test_archives_then_deletes_with_unregistered(self):
        inst = self.source()
        p = inst.prefix
        dot = os.path.join(self.site.home, ".macports")
        ask = b.Ask([True])
        lines = self.run_phase(inst, ask=ask)
        self.assertEqual(self.fake.archived(), [[p + "/var/db"], [p + "/etc"], [dot], [p + "/var/log"]])
        for path in (p + "/var/db", p + "/etc", dot, p + "/var/log"):
            self.assertTrue(os.path.isfile(self.site.archive(path)), path)
        self.assertEqual(len(ask.asked), 1)
        self.assertIn(f"    {p}/var/log/", lines)
        self.assertIn(f"    {p}/etc/app.conf", lines)
        self.assertFalse(os.path.lexists(p))
        self.assertFalse(os.path.lexists(dot))
        self.assertTrue(all(sudo for sudo, _ in self.fake.ran(rm.RM)))
        last_tar = max(i for i, (_, argv) in enumerate(self.fake.commands) if argv[0] == rm.TAR)
        self.assertLess(self.fake.index(rm.LSOF), self.fake.index(rm.TAR))
        self.assertLess(last_tar, self.fake.index(rm.RM))

    def test_identity_journaled_before_first_deletion(self):
        inst = self.source()
        self.run_phase(inst)
        ids = [e.get("action_id") for e in self.site.journal()]
        identity = ids.index("6.identity." + state.slug(inst.prefix))
        first_delete = next(i for i, a in enumerate(ids) if str(a).startswith("6.delete."))
        self.assertLess(identity, first_delete)
        record = self.site.journal()[identity]
        self.assertEqual((record["prefix"], record["manager"], record["markers"]), (inst.prefix, "ports", [CONF]))
        self.assertEqual(tuple(record["identity"]), tuple(inst.identity))

    def test_process_in_prefix_stops_and_restarts(self):
        inst = self.source(drivable=False)
        p = inst.prefix
        svc = self.service(inst)
        self.fake.lsof = b.lsof_output([
            (1, [("cwd", "/"), ("txt", "/sbin/launchd")]),
            (4321, [("cwd", p + "/var/db/app"), ("txt", "/usr/bin/sqlite3"), ("3", p + "/var/db/app/data.db")])])
        with self.assertRaises(rm.Stopped) as cm:
            self.run_phase(inst, [svc])
        exc = cm.exception
        self.assertIsInstance(exc, r.ActionFailed)
        self.assertIn(f"1 process still uses {p}", str(exc))
        self.assertIn(f"    PID 4321 /usr/bin/sqlite3: {p}/var/db/app, {p}/var/db/app/data.db", exc.lines)
        self.assertEqual(self.fake.archived(), [])
        self.assertEqual(self.fake.removed(), [])
        bootout = self.fake.index(b.LAUNCHCTL, "bootout", "system/org.macports.app")
        lsof = self.fake.index(rm.LSOF)
        bootstrap = self.fake.index(b.LAUNCHCTL, "bootstrap", "system", svc.plist)
        self.assertLess(bootout, lsof)
        self.assertLess(lsof, bootstrap)
        self.assertIn("  started again: org.macports.app", exc.lines)
        self.assertTrue(os.path.isfile(os.path.join(p, CONF)))

    def test_lsof_that_fails_stops_the_phase(self):
        inst = self.source()
        self.fake.lsof_exit = 2
        with self.assertRaises(rm.Stopped) as cm:
            self.run_phase(inst)
        self.assertIn("sudo lsof exited 2", str(cm.exception))
        self.assertEqual(self.fake.archived(), [])

    def test_too_little_space_stops_before_archives(self):
        inst = self.source()
        p = inst.prefix
        self.site.free = 512 << 20
        with self.assertRaises(rm.Stopped) as cm:
            self.run_phase(inst)
        self.assertIn("plus 1 GiB", str(cm.exception))
        (sudo, du), = self.fake.ran(rm.DU)
        self.assertTrue(sudo)
        self.assertEqual(list(du[2:]), [p + "/var/db", p + "/etc", self.site.home + "/.macports", p + "/var/log"])
        self.assertEqual(self.fake.archived(), [])
        self.assertEqual(self.fake.removed(), [])

    def test_a_size_du_does_not_report_stops_the_phase(self):
        inst = self.source()
        self.fake.du_missing = {inst.prefix + "/etc"}
        with self.assertRaises(rm.Stopped) as cm:
            self.run_phase(inst)
        self.assertIn(f"sudo du gave no size for {inst.prefix}/etc", str(cm.exception))

    def test_failed_archive_stops_before_deletion(self):
        inst = self.source(drivable=False)
        p = inst.prefix
        svc = self.service(inst)
        self.fake.tar_fail = {p + "/etc"}
        with self.assertRaises(rm.Stopped) as cm:
            self.run_phase(inst, [svc])
        self.assertEqual(cm.exception.result.action_id, "6.archive." + state.slug(p + "/etc"))
        self.assertEqual(self.fake.removed(), [])
        self.fake.index(b.LAUNCHCTL, "bootstrap", "system", svc.plist)
        results = [e["result"] for e in self.site.journal()
                   if e.get("action_id") == "6.archive." + state.slug(p + "/etc") and "result" in e]
        self.assertEqual(results, ["failed"])

    def test_remaining_port_stops_the_phase(self):
        inst = self.source()
        shutil.rmtree(os.path.join(inst.portdbpath, "registry"))
        make_registry(inst.portdbpath, ports=[port(1, "wget", "1.25.0", state="imaged")])
        with self.assertRaises(rm.Stopped) as cm:
            self.run_phase(inst)
        self.assertIn("still holds 1 port", str(cm.exception))
        self.assertIn("    wget @1.25.0_0", cm.exception.lines)
        self.assertEqual(self.fake.ran(rm.LSOF), [])

    def test_target_never_removed_even_when_named(self):
        target = self.site.target_macports("opt/local")
        self.fake.homes["/Users/macports"] = os.path.join(target.prefix, "var", "macports", "home")
        plan = self.site.plan(target, [target], [target])
        lines = self.site.run(plan, self.site.bundle([target]))
        self.assertIn(f"  left in place, nothing archived or deleted: {target.prefix} is the target of this plan",
                      lines)
        self.assertEqual(self.fake.commands, [])
        self.assertTrue(os.path.isfile(os.path.join(target.prefix, CONF)))

    def test_a_plan_that_names_no_instance_does_nothing(self):
        inst = self.source()
        plan = self.site.plan(self.target, [self.target, inst], [])
        self.assertEqual(self.site.run(plan, self.site.bundle([self.target, inst])), [])
        self.assertEqual(self.fake.commands, [])

    @unittest.skipIf(os.geteuid() == 0, "root reads every directory")
    def test_unreadable_var_directory_archived_by_sudo(self):
        inst = self.source()
        p = inst.prefix
        locked = os.path.join(p, "var", "db", "secret")
        os.makedirs(locked)
        os.chmod(locked, 0)

        def unlock():
            if os.path.isdir(locked):
                os.chmod(locked, 0o755)
        self.addCleanup(unlock)
        lines = self.run_phase(inst)
        tar = [(sudo, argv) for sudo, argv in self.fake.ran(rm.TAR) if (p + "/var/db").lstrip("/") in argv]
        self.assertEqual([sudo for sudo, _ in tar], [True])
        self.assertIn(f"    {p}/var/db/", lines)
        self.assertFalse(os.path.lexists(p))

    def test_a_prefix_without_macports_conf_is_left_in_place(self):
        inst = self.source()
        os.unlink(os.path.join(inst.prefix, CONF))
        lines = self.run_phase(inst)
        self.assertIn(f"  left in place, nothing archived or deleted: {inst.prefix} holds no {CONF}", lines)
        self.assertEqual(self.fake.commands, [])
        self.assertTrue(os.path.isdir(inst.prefix))

    def test_user_jobs_and_unowned_plists_stay(self):
        inst = self.source()
        mine = b.write_plist(os.path.join(self.site.library, "LaunchDaemons", "org.macports.mine.plist"),
                             "org.macports.mine", os.path.join(inst.prefix, "bin", "mine"))
        job = b.service("org.macports.mine", mine, inst.prefix, owned=False, scope="system",
                        program=os.path.join(inst.prefix, "bin", "mine"))
        lines = self.run_phase(inst, [job])
        self.assertIn(f"  will stop working: {mine} runs {inst.prefix}/bin/mine; edit or remove it by hand",
                      lines)
        self.assertIn(f"  never deleted: {mine} (no plist MacPorts owns, or one the tool could not read)", lines)
        self.assertTrue(os.path.isfile(mine))
        self.assertNotIn(mine, self.fake.removed())


class UnregisteredTest(MacPortsTest):
    """The unregistered entries of a MacPorts prefix: their listing, their archives and the "no" that keeps them"""

    def test_no_keeps_the_prefix_and_journals_it(self):
        inst = self.source()
        p = inst.prefix
        apps = self.site.mkdir("Applications", "MacPorts")
        svc = self.service(inst, loaded=False)
        self.fake.receipt = [p.lstrip("/") + "/bin/port"]
        self.fake.homes["/Users/macports"] = p + "/var/macports/home"
        lines = self.run_phase(inst, [svc], b.Ask([False]))
        self.assertTrue(os.path.isfile(p + "/var/log/app.log"))
        self.assertTrue(os.path.isfile(os.path.join(p, CONF)))
        removed = self.fake.removed()
        self.assertNotIn(p, removed)
        self.assertEqual([x for x in removed if x in (apps, svc.plist)], [apps, svc.plist])
        self.assertFalse(os.path.lexists(apps))
        self.assertFalse(os.path.lexists(svc.plist))
        keeps = [e for e in self.site.journal() if e.get("action_id") == "6.keep." + state.slug(p)]
        self.assertEqual([(k["result"], k["prefix"]) for k in keeps], [("keep", p)])
        self.assertEqual(envclean.phase6_keeps(self.site.run_dir.journal), [p])
        self.assertEqual(self.deletes(rm.PKGUTIL, "--forget"), [])
        self.assertEqual(self.deletes(rm.DSCL, "-delete"), [])
        self.assertNotIn([p + "/var/log"], self.fake.archived())
        self.assertIn(f"  kept: {p} stays with its unregistered entries; the rest of its delete list goes", lines)

    def test_undrivable_registered_files_go_unarchived(self):
        inst = self.site.macports(drivable=False)
        p = inst.prefix
        registered = [os.path.join(p, "bin", "wget"), os.path.join(p, "lib", "libwget.dylib"),
                      os.path.join(p, "share", "man", "man1", "wget.1")]
        for path in registered:
            b.write(path)
        stray = b.write(os.path.join(p, "lib", "stray.dylib"))
        self.site.phase1_registry(inst, [port(1, "wget", "1.25.0")], [(1, f, None, 1, 0) for f in registered])
        ask = b.Ask([True])
        lines = self.run_phase(inst, ask=ask)
        archived = [path for call in self.fake.archived() for path in call]
        self.assertEqual(archived, [p + "/etc", stray])
        self.assertIn(f"  1 unregistered entry in {p}, neither base's nor under var/macports nor registered to a port:",
                      lines)
        self.assertIn("    " + stray, lines)
        listing = [line for line in lines if line.startswith("    ")]
        self.assertFalse([line for line in listing if "wget" in line])
        self.assertFalse(os.path.lexists(p))

    def test_without_a_phase_1_backup_a_fresh_registry_decides(self):
        inst = self.site.macports(drivable=False)
        p = inst.prefix
        if inst.portdbpath is None:
            self.fail("the MacPorts instance has no portdbpath")
        b.write(os.path.join(p, "bin", "wget"))
        shutil.rmtree(os.path.join(inst.portdbpath, "registry"))
        make_registry(inst.portdbpath, ports=[port(1, "wget", "1.25.0")],
                      files=[(1, os.path.join(p, "bin", "wget"), None, 1, 1)])
        lines = self.run_phase(inst, ask=b.Ask([True]))
        self.assertFalse([line for line in lines if line.startswith("    ") and "wget" in line])


class MacPortsUserTest(MacPortsTest):
    """The macports user and group: deleted with the prefix, kept for a survivor, left alone elsewhere"""

    def test_the_macports_user_and_group_go_before_the_prefix(self):
        inst = self.source()
        p = inst.prefix
        home = os.path.join(p, "var", "macports", "home")
        os.makedirs(home)
        self.fake.homes["/Users/macports"] = home
        lines = self.run_phase(inst)
        user = self.fake.index(rm.DSCL, "-delete", "/Users/macports")
        group = self.fake.index(rm.DSCL, "-delete", "/Groups/macports")
        prefix = self.fake.index(rm.RM, p)
        self.assertLess(user, group)
        self.assertLess(group, prefix)
        self.assertTrue(self.fake.commands[user][0] and self.fake.commands[group][0])
        self.assertIn("  deleted the macports user and group", lines)
        self.assertFalse(os.path.lexists(p))

    def test_staying_macports_user_keeps_its_home(self):
        other = self.site.macports("opt/local2")
        inst = self.source()
        p = inst.prefix
        home = os.path.join(p, "var", "macports", "home")
        pref = b.write(os.path.join(home, "Library", "Preferences", "x.plist"))
        self.fake.homes["/Users/macports"] = home
        lines = self.run_phase(inst, others=[other])
        self.assertEqual(self.deletes(rm.DSCL, "-delete"), [])
        self.assertTrue(os.path.isfile(pref))
        for gone in ("bin", "etc", "libexec", "var/db", "var/log", "var/macports/registry"):
            self.assertFalse(os.path.lexists(os.path.join(p, gone)), gone)
        self.assertNotIn(p, self.fake.removed())
        self.assertIn("  the macports user stays, because another MacPorts instance survives", lines)
        self.assertIn(f"  left in place: {home}, the home of the macports user, which stays", lines)
        self.assertTrue(os.path.isdir(os.path.join(self.site.home, ".macports")))

    def test_a_user_whose_home_lies_elsewhere_is_left_alone(self):
        inst = self.source()
        self.fake.homes["/Users/macports"] = self.site.path("opt", "local9", "var", "macports", "home")
        self.run_phase(inst)
        self.assertEqual(self.deletes(rm.DSCL, "-delete"), [])
        self.assertFalse(os.path.lexists(inst.prefix))


class SecondInstanceTest(MacPortsTest):
    """The paths MacPorts instances share: kept while another survives, removed with the last"""

    def test_second_instance_keeps_shared_paths(self):
        target = self.site.target_macports("opt/local")
        inst = self.site.macports("opt/local2")
        p = inst.prefix
        apps = os.path.join(self.site.applications, "MacPorts")
        theirs = b.write(os.path.join(apps, "Target.app", "Contents", "Info.plist"))
        legacy = b.write(os.path.join(self.site.library, "Receipts", "MacPorts-2.8.1.pkg", "Contents", "Info.plist"))
        dot = os.path.join(self.site.home, ".macports")
        b.write(os.path.join(dot, "macports.conf"), "# the user's settings\n")
        self.site.phase1_registry(inst, [port(1, "gimp", "2.10.38")],
                                  [(1, os.path.join(apps, "GIMP.app", "Contents", "MacOS", "gimp"), None, 1, 1)])
        self.fake.receipt = [target.prefix.lstrip("/") + "/bin/port"]
        self.fake.homes["/Users/macports"] = os.path.join(target.prefix, "var", "macports", "home")
        lines = self.run_phase(inst, target=target)
        self.assertFalse(os.path.lexists(p))
        self.assertTrue(os.path.isfile(os.path.join(target.prefix, CONF)))
        self.assertTrue(os.path.isfile(theirs))
        self.assertIn(f"  never deleted: {apps} (it holds entries no port of this instance registered: {theirs})",
                      lines)
        self.assertTrue(os.path.isfile(legacy))
        self.assertTrue(os.path.isdir(dot))
        self.assertIn([dot], self.fake.archived())
        self.assertEqual(self.deletes(rm.DSCL, "-delete"), [])
        self.assertEqual(self.deletes(rm.PKGUTIL, "--forget"), [])
        self.assertTrue(all(self.site.tmp in path for path in self.fake.removed()))

    def test_last_instance_takes_shared_paths(self):
        inst = self.source()
        legacy = b.write(os.path.join(self.site.library, "Receipts", "MacPorts-2.8.1.pkg", "Contents", "Info.plist"))
        tcl = b.write(os.path.join(self.site.library, "Tcl", "macports1.0", "macports.tcl"))
        self.run_phase(inst)
        self.assertFalse(os.path.lexists(os.path.dirname(os.path.dirname(legacy))))
        self.assertFalse(os.path.lexists(os.path.dirname(tcl)))
        self.assertFalse(os.path.lexists(os.path.join(self.site.home, ".macports")))


class ReceiptTest(MacPortsTest):
    """The MacPorts installer receipt: forgotten after its prefix, kept when it names another"""

    def test_receipt_forgotten_after_the_prefix(self):
        inst = self.source()
        p = inst.prefix
        rel = p.lstrip("/")
        parents = [rel.rsplit("/", n)[0] for n in range(rel.count("/"), 0, -1)]
        self.fake.receipt = parents + [rel, rel + "/bin", rel + "/bin/port", rel + "/libexec/macports/bin/tclsh8.6"]
        lines = self.run_phase(inst)
        forget = self.fake.index(rm.PKGUTIL, "--forget", rm.PKG_ID)
        self.assertLess(self.fake.index(rm.RM, p), forget)
        self.assertTrue(self.fake.commands[forget][0])
        self.assertIn(f"  forgot the installer receipt {rm.PKG_ID}", lines)

    def test_a_receipt_for_another_prefix_stays(self):
        inst = self.source()
        self.fake.receipt = [self.site.path("opt", "elsewhere").lstrip("/") + "/bin/port"]
        lines = self.run_phase(inst)
        self.assertEqual(self.deletes(rm.PKGUTIL, "--forget"), [])
        self.assertIn(f"  the MacPorts installer receipt names files outside {inst.prefix}: it stays", lines)


class ResumeTest(MacPortsTest):
    """A resumed phase 6: archives taken again or kept, services booted out again, identity records"""

    def test_resume_before_deletion_retakes_archives(self):
        inst = self.source()
        p = inst.prefix
        self.fake.tar_fail = {p + "/etc"}
        with self.assertRaises(rm.Stopped):
            self.run_phase(inst)
        self.assertEqual(self.fake.archived(), [[p + "/var/db"], [p + "/etc"]])
        self.fake.tar_fail = set()
        self.fake.commands.clear()
        self.run_phase(inst, resumed=True)
        self.assertEqual(self.fake.archived()[:3], [[p + "/var/db"], [p + "/etc"], [self.site.home + "/.macports"]])
        self.assertFalse(os.path.lexists(p))

    def test_resume_after_deletion_keeps_archives(self):
        inst = self.source()
        p = inst.prefix
        dot = os.path.join(self.site.home, ".macports")
        apps = self.site.mkdir("Applications", "MacPorts")
        self.fake.rm_fail = self.fake.rm_fail_root = {apps, dot}
        with self.assertRaises(rm.Stopped) as cm:
            self.run_phase(inst)
        self.assertIn(apps, str(cm.exception))
        self.assertFalse(os.path.lexists(p))
        self.fake.rm_fail = self.fake.rm_fail_root = set()
        self.fake.commands.clear()
        lines = self.run_phase(inst, resumed=True)
        self.assertEqual(self.fake.archived(), [])
        self.assertIn(f"  kept from the first attempt: {self.site.archive(dot)}", lines)
        self.assertTrue(self.fake.ran(rm.LSOF))
        self.assertFalse(os.path.lexists(apps))
        self.assertFalse(os.path.lexists(dot))
        identities = [e for e in self.site.journal() if e.get("action_id") == "6.identity." + state.slug(p)]
        self.assertEqual([e["markers"] for e in identities], [[CONF], [CONF]])

    def test_resume_boots_restarted_services_out(self):
        inst = self.source(drivable=False)
        p = inst.prefix
        svc = self.service(inst)
        self.fake.tar_fail = {p + "/etc"}
        with self.assertRaises(rm.Stopped):
            self.run_phase(inst, [svc])
        self.fake.index(b.LAUNCHCTL, "bootstrap", "system", svc.plist)
        # The service ran again after the stop and wrote to its data.
        self.fake.jobs[("system", svc.label)] = [b.printed("system", svc.label, svc.plist, svc.program, pid=5151)]
        self.fake.tar_fail = set()
        self.fake.commands.clear()
        self.run_phase(inst, [svc], resumed=True)
        self.assertLess(self.fake.index(b.LAUNCHCTL, "bootout", "system/" + svc.label), self.fake.index(rm.TAR))
        self.assertEqual(self.fake.archived()[:2], [[p + "/var/db"], [p + "/etc"]])
        self.assertFalse(os.path.lexists(p))
        self.assertFalse([argv for _, argv in self.fake.ran(b.LAUNCHCTL) if argv[1] == "bootstrap"])

    def test_resume_after_process_stop_probes_again(self):
        inst = self.source()
        p = inst.prefix
        self.fake.lsof = b.lsof_output([(88, [("cwd", p + "/var/db"), ("txt", "/usr/bin/sqlite3")])])
        with self.assertRaises(rm.Stopped):
            self.run_phase(inst)
        self.fake.lsof = ""
        self.fake.commands.clear()
        self.run_phase(inst, resumed=True)
        self.assertEqual(len(self.fake.ran(rm.LSOF)), 1)
        self.assertFalse(os.path.lexists(p))

    def test_record_of_another_directory_is_refused(self):
        inst = self.source()
        os.unlink(os.path.join(inst.prefix, CONF))
        self.site.run_dir.journal.append({"phase": 6, "action_id": "6.identity." + state.slug(inst.prefix),
                                          "prefix": inst.prefix, "identity": [1, 2], "markers": [CONF]})
        lines = self.run_phase(inst, resumed=True)
        self.assertIn(f"  left in place, nothing archived or deleted: {inst.prefix} holds no {CONF}", lines)
        self.assertTrue(os.path.isdir(inst.prefix))


class SafetyTest(MacPortsTest):
    """The safety rules, each refusing a path the delete list names"""

    def test_every_safety_rule_refuses_its_path(self):
        home = self.site.home
        inst = self.source(apps=home)
        under_target = b.write(os.path.join(self.target.prefix, "Library", "LaunchDaemons", "org.macports.t.plist"))
        holds_target = os.path.dirname(self.target.prefix)
        refused = {home: "it is your home folder, or holds it",
                   os.path.dirname(home): "it is your home folder, or holds it",
                   under_target: f"it belongs to Homebrew at {self.target.prefix}, which stays",
                   holds_target: f"it holds {self.target.prefix}, which stays",
                   "/var": "it is a system folder"}
        services = [b.service(f"org.macports.s{n}", path, inst.prefix, f"s{n}", kind="port", scope="system")
                    for n, path in enumerate(sorted(refused)) if path != home]
        lines = self.run_phase(inst, services)
        for path, why in refused.items():
            self.assertIn(f"  never deleted: {path} ({why})", lines)
            self.assertNotIn(path, self.fake.removed())
            self.assertTrue(os.path.lexists(path), path)
        self.assertFalse(os.path.lexists(inst.prefix))
        self.assertTrue(os.path.isdir(self.target.prefix))


# Parsers -----------------------------------------------------------------------------------------

class ParsersTest(TempDirTest):
    """The parsers and journal readers phase 6 relies on: lsof, du, git status, receipts and unregistered units"""

    def test_parse_lsof_keeps_each_file_with_its_descriptor(self):
        text = ("p12\ncsqlite3\nfcwd\nn/opt/local/var/db\nftxt\nn/usr/bin/sqlite3\nf3\nn/opt/local/var/db/x.db\n"
                "p13\nfcwd\nn/\n")
        procs = rm.parse_lsof(text)
        self.assertEqual([(p.pid, p.program) for p in procs], [(12, "sqlite3"), (13, None)])
        self.assertEqual(procs[0].files, [("cwd", "/opt/local/var/db"), ("txt", "/usr/bin/sqlite3"),
                                          ("3", "/opt/local/var/db/x.db")])

    def test_the_program_of_a_process_is_its_first_txt_file(self):
        procs = rm.parse_lsof(b.lsof_output([(9, [("cwd", "/"), ("txt", "/opt/local/bin/mysqld"),
                                                  ("txt", "/usr/lib/dyld")])]))
        self.assertEqual(procs[0].program, "/opt/local/bin/mysqld")

    def test_processes_count_only_names_under_the_owned_roots(self):
        usr = self.path("usr", "local")
        for sub in ("Cellar/foo/1.0/bin", "Homebrew", "opt", "var/homebrew", "Caskroom", "go/bin"):
            os.makedirs(os.path.join(usr, sub))
        inst = make_instance(Manager.BREW, usr, identity=system.identity(usr), spellings=(usr,),
                             owned_roots=tuple(os.path.join(usr, r) for r in
                                               ("Cellar", "Caskroom", "Homebrew", "opt", "var/homebrew")))
        procs = rm.parse_lsof(b.lsof_output([
            (1, [("cwd", usr + "/go"), ("txt", usr + "/go/bin/go")]),
            (2, [("cwd", "/"), ("txt", usr + "/Cellar/foo/1.0/bin/foo")]),
            (3, [("cwd", "/tmp"), ("0", "/dev/null")])]))
        hits = rm.processes_under(procs, env.PrefixIndex([inst]))
        self.assertEqual([(p.pid, names) for p, names in hits], [(2, [usr + "/Cellar/foo/1.0/bin/foo"])])

    def test_parse_du_reads_one_size_per_path(self):
        text = "120\t/opt/local/var/db\n4\t/Users/alice/.macports\ndu: /x: Permission denied\n"
        self.assertEqual(rm.parse_du(text), {"/opt/local/var/db": 120, "/Users/alice/.macports": 4})

    def test_parse_porcelain_renames_quotes_untracked(self):
        text = (' M Library/Homebrew/cmd/a.rb\n?? untracked/\nR  old.rb -> new.rb\n?? "with\\ttab.rb"\n'
                'A  "caf\\303\\251.rb"\n')
        self.assertEqual(rm.parse_porcelain(text), ["Library/Homebrew/cmd/a.rb", "untracked", "old.rb", "new.rb",
                                                    "with\ttab.rb", "café.rb"])

    def test_receipt_under_ignores_leading_dirs(self):
        prefix = self.path("opt", "local")
        os.makedirs(prefix)
        inst = make_instance(Manager.PORTS, prefix, identity=system.identity(prefix), spellings=(prefix,))
        self.assertTrue(rm.receipt_under([os.path.dirname(prefix), prefix, prefix + "/bin/port"], inst))
        self.assertFalse(rm.receipt_under([prefix + "/bin/port", "/Library/LaunchDaemons/org.macports.x.plist"], inst))
        self.assertFalse(rm.receipt_under([os.path.dirname(prefix)], inst))
        self.assertFalse(rm.receipt_under([self.path("opt", "local2", "bin", "port")], inst))

    def test_deletion_begun_after_identity_record(self):
        argv = ["/bin/rm", "-rf", "x"]
        entries = [{"phase": 6, "action_id": "6.archive.%opt%local%etc", "argv": ["/usr/bin/tar"]},
                   {"phase": 6, "action_id": "6.identity.%opt%local"},
                   {"phase": 6, "action_id": "6.delete.%opt%local", "result": "ok"},
                   {"phase": 6, "action_id": "6.identity.%opt%local2"},
                   {"phase": 6, "action_id": "6.delete.%opt%local2", "argv": argv}]
        self.assertFalse(rm.deletion_begun(entries, "/opt/local"))
        self.assertTrue(rm.deletion_begun(entries, "/opt/local2"))
        entries += [{"phase": 6, "action_id": "6.identity.%opt%local"},
                    {"phase": 6, "action_id": "6.links.%opt%local%bin", "argv": argv}]
        self.assertTrue(rm.deletion_begun(entries, "/opt/local"))
        self.assertFalse(rm.deletion_begun([{"phase": 5, "action_id": "6.identity.%opt%local"},
                                            {"phase": 5, "action_id": "6.delete.%opt%local", "argv": argv}],
                                           "/opt/local"))

    @unittest.skipIf(os.geteuid() == 0, "root reads every directory")
    def test_unregistered_units_whole_and_unreadable(self):
        root = self.path("p")
        for rel in ("var/db/a/1", "var/db/a/2", "var/macports/x", "bin/port", "bin/stray", "share/doc/x/readme"):
            b.write(os.path.join(root, rel))
        os.makedirs(os.path.join(root, "empty", "sub"))
        locked = os.path.join(root, "var", "locked")
        os.makedirs(locked)
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o755)
        found = rm.unregistered_units(root, [os.path.join(root, "var", "macports")],
                                      lambda path: not path.endswith("/bin/port"))
        self.assertEqual(found.units, [os.path.join(root, "bin", "stray"), os.path.join(root, "share"),
                                       os.path.join(root, "var", "db"), locked])
        self.assertEqual(found.count, 5)

    def test_unregistered_units_of_a_prefix_that_is_gone(self):
        self.assertEqual(rm.unregistered_units(self.path("gone"), [], lambda path: True), rm.Unregistered())


if __name__ == "__main__":
    unittest.main()

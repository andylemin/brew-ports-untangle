"""Phase 6 for Homebrew: local repository state, the enumerated list, its links and emptied directories

Also dedicated prefixes and `/usr/local`, `/etc/paths.d/homebrew`, Applications links, caches, plists,
preconditions and casks.
"""

import os
import shutil
import unittest
from unittest import mock

from brew_ports import model, remove_manager as rm, runner as r, snapshot, state
from brew_ports.model import Confidence
from tests.unit.fixtures.remove_manager import builders as b
from tests.unit.helpers import TempDirTest, make_package


class HomebrewTest(TempDirTest):
    """The site and the phase 6 run of the Homebrew removal tests, with a MacPorts target"""

    def setUp(self):
        super().setUp()
        self.site = b.Site(self.tmp)
        self.fake = self.site.fake
        self.target = self.site.target_macports("opt/local")

    def run_phase(self, inst, services=(), ask=None, others=(), environ=None, **plan_kw):
        """Run phase 6 over a plan that names `inst`, beside the target and `others`

        @param inst      the Homebrew instance the plan removes
        @param services  the services of the scan bundle
        @param ask       answers the prompts; None answers yes
        @param others    further instances on the host
        @param environ   variables added to the user's environment
        @param plan_kw   further fields of the plan
        @returns         the report lines
        """
        instances = [self.target, inst] + list(others)
        plan = self.site.plan(self.target, instances, [inst], **plan_kw)
        return self.site.run(plan, self.site.bundle(instances, services), ask, environ=environ)

    def last_tar(self):
        """Return the position of the last `tar` command

        @returns  its index in the fake host's commands
        """
        return max(i for i, (_, argv) in enumerate(self.fake.commands) if argv[0] == rm.TAR)


class DedicatedPrefixTest(HomebrewTest):
    """A dedicated prefix: its remaining entries behind a second confirmation, and the space they need"""

    def test_prefix_goes_after_its_remaining_entries(self):
        inst = self.site.homebrew()
        p = inst.prefix
        stale = b.link("../Cellar/oldtool/2.0/bin/oldtool", os.path.join(p, "bin", "oldtool"))
        b.write(os.path.join(p, "mydata", "notes.txt"))
        ask = b.Ask([True])
        lines = self.run_phase(inst, ask=ask)
        self.assertEqual(self.fake.archived(), [[p + "/var"], [p + "/etc"], [p + "/mydata"]])
        self.assertEqual(ask.asked, [f"Delete {p} with these items?"])
        self.assertIn(f"  {p} still holds 3 items that Homebrew's own uninstall leaves: etc, mydata, var", lines)
        self.assertIn(f"  y saves them in the run folder, then deletes them and {p} itself.", lines)
        self.assertIn(f"  n keeps {p} with them. Homebrew itself is already gone from it.", lines)
        self.assertIn(stale, self.fake.removed())
        self.assertFalse(os.path.lexists(p))
        self.assertIn("6.delete." + state.slug(p), [e.get("action_id") for e in self.site.journal()])
        self.assertFalse([argv for sudo, argv in self.fake.ran(rm.RM) if sudo])

    def test_a_no_leaves_the_remaining_entries_and_the_prefix(self):
        inst = self.site.homebrew()
        p = inst.prefix
        b.write(os.path.join(p, "mydata", "notes.txt"))
        lines = self.run_phase(inst, ask=b.Ask([False]))
        for gone in ("Cellar", "Caskroom", "Library", ".git", "README.md", "bin", "var/homebrew"):
            self.assertFalse(os.path.lexists(os.path.join(p, gone)), gone)
        for kept in ("mydata/notes.txt", "var/log/wget.log", "etc/wgetrc"):
            self.assertTrue(os.path.isfile(os.path.join(p, kept)), kept)
        self.assertIn(f"  {p} stays with etc, mydata, var, as you answered.", lines)
        self.assertEqual(self.fake.archived(), [[p + "/var"], [p + "/etc"]])
        self.assertFalse([e for e in self.site.journal() if str(e.get("action_id")).startswith("6.keep.")])

    def test_space_check_counts_remaining_entries(self):
        inst = self.site.homebrew()
        p = inst.prefix
        b.write(os.path.join(p, "mydata", "notes.txt"))
        self.run_phase(inst)
        (_, du), = self.fake.ran(rm.DU)
        self.assertEqual(list(du[2:]), [p + "/var", p + "/etc", p + "/bin", p + "/mydata"])


class RepositoryTest(HomebrewTest):
    """The repository's local state: changes, commits and a stash archived with `.git`, a clean one not"""

    def test_local_changes_archived_with_git_dir(self):
        inst = self.site.homebrew()
        p = inst.prefix
        b.write(os.path.join(p, "Library", "Homebrew", "cmd", "local.rb"))
        b.write(os.path.join(p, "untracked", "notes.txt"))
        self.fake.git["status"] = r.FakeResponse(
            stdout=" M Library/Homebrew/cmd/local.rb\n?? untracked/\n D Library/Homebrew/gone.rb\n")
        lines = self.run_phase(inst)
        repo = [call for call in self.fake.archived() if p + "/.git" in call]
        self.assertEqual(repo, [[p + "/.git", p + "/Library/Homebrew/cmd/local.rb", p + "/untracked"]])
        self.assertTrue(os.path.isfile(self.site.archive(p + ".repository")))
        self.assertLess(self.fake.index(rm.TAR, p.lstrip("/") + "/.git"), self.fake.index(rm.RM))
        self.assertIn(f"  Homebrew's own files in {p} hold changes of yours (3 changed paths); they are saved too.",
                      lines)
        self.assertFalse(os.path.lexists(p))

    def test_a_stash_alone_archives_the_git_directory(self):
        inst = self.site.homebrew()
        self.fake.git["rev-parse"] = r.FakeResponse(stdout="0123abcd\n")
        lines = self.run_phase(inst)
        self.assertIn([inst.prefix + "/.git"], self.fake.archived())
        self.assertIn(f"  Homebrew's own files in {inst.prefix} hold changes of yours (a stash); they are saved too.",
                      lines)

    def test_local_commits_alone_archive_the_git_directory(self):
        inst = self.site.homebrew()
        self.fake.git["rev-list"] = r.FakeResponse(stdout="2\n")
        lines = self.run_phase(inst)
        self.assertIn([inst.prefix + "/.git"], self.fake.archived())
        self.assertIn(f"  Homebrew's own files in {inst.prefix} hold changes of yours (2 local commits); they are "
                      "saved too.", lines)

    def test_unreadable_repository_archives_git_dir(self):
        inst = self.site.homebrew()
        self.fake.git["status"] = r.FakeResponse(exit=128, stderr="fatal: detected dubious ownership\n")
        lines = self.run_phase(inst)
        self.assertIn([inst.prefix + "/.git"], self.fake.archived())
        self.assertIn(f"  Homebrew's own files in {inst.prefix} hold changes of yours (git status exited 128); they "
                      "are saved too.", lines)

    def test_a_clean_repository_is_not_archived(self):
        inst = self.site.homebrew()
        self.run_phase(inst)
        self.assertFalse([call for call in self.fake.archived() if inst.prefix + "/.git" in call])
        self.assertFalse(os.path.exists(self.site.archive(inst.prefix + ".repository")))
        statuses = [argv for _, argv in self.fake.ran(rm.GIT) if "status" in argv]
        self.assertEqual(statuses, [(rm.GIT, "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", inst.prefix,
                                     "status", "--porcelain")])


class UsrLocalTest(HomebrewTest):
    """Homebrew at `/usr/local`: only its own entries go, the prefix and the shared directories stay"""

    def test_usr_local_loses_only_homebrews_entries_and_stays(self):
        inst = self.site.homebrew(usr_local=True, drivable=False)
        u = inst.prefix
        go = b.write(os.path.join(u, "go", "bin", "go"), "#!/bin/sh\n", 0o755)
        go_link = b.link("../go/bin/go", os.path.join(u, "bin", "go"))
        tex = b.write(os.path.join(u, "texlive", "2025", "bin", "tex"))
        go_man = b.write(os.path.join(u, "share", "man", "man1", "go.1"))
        self.fake.lsof = b.lsof_output([(500, [("cwd", u + "/go"), ("txt", go)])])
        ask = b.Ask()
        lines = self.run_phase(inst, ask=ask)
        self.assertEqual(ask.asked, [])
        for kept in (go, go_link, tex, go_man):
            self.assertTrue(os.path.lexists(kept), kept)
        for gone in ("Homebrew", "Cellar", "Caskroom", "opt", "var/homebrew", "bin/brew", "bin/wget",
                     "share/man/man1/wget.1"):
            self.assertFalse(os.path.lexists(os.path.join(u, gone)), gone)
        self.assertTrue(os.path.isdir(u))
        self.assertNotIn(u, self.fake.removed())
        self.assertIn(f"  {u} stays, because other installers use it too. It still holds: bin, etc, go, share, "
                      "texlive, var", lines)

    def test_usr_local_shared_directories_stay(self):
        inst = self.site.homebrew(usr_local=True, drivable=False)
        u = inst.prefix
        self.run_phase(inst)
        self.assertTrue(os.path.isdir(os.path.join(u, "bin")))
        self.assertTrue(os.path.isdir(os.path.join(u, "share")))
        self.assertFalse(os.path.lexists(os.path.join(u, "share", "man")))
        self.assertFalse(os.path.lexists(os.path.join(u, "opt")))


class SystemFilesTest(HomebrewTest):
    """The files outside the prefix: `/etc/paths.d/homebrew`, Applications links, and a path only root can remove"""

    def test_paths_d_homebrew_backed_up_then_deleted(self):
        inst = self.site.homebrew()
        path = b.write(os.path.join(self.site.etc_paths_d, "homebrew"), inst.prefix + "/bin\n")
        self.run_phase(inst)
        mkdir = self.fake.index(r.MKDIR, "-p")
        cp = self.fake.index(r.CP, path)
        delete = self.fake.index(rm.RM, path)
        self.assertLess(mkdir, cp)
        self.assertLess(cp, delete)
        self.assertTrue(self.fake.commands[cp][0] and self.fake.commands[delete][0])
        self.assertFalse(os.path.lexists(path))

    def test_etc_paths_d_homebrew_with_other_lines_stays(self):
        inst = self.site.homebrew()
        path = b.write(os.path.join(self.site.etc_paths_d, "homebrew"), inst.prefix + "/bin\n/opt/X11/bin\n")
        lines = self.run_phase(inst)
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(self.fake.ran(r.CP), [])
        self.assertIn(f"  {path} stays: it names more than {inst.prefix}/bin.", lines)

    def test_application_links_go_other_apps_stay(self):
        inst = self.site.homebrew(drivable=False)
        keg = os.path.join(inst.prefix, "Cellar", "wget", "1.25.0")
        system_link = b.link(keg, os.path.join(self.site.applications, "Wget.app"))
        user_link = b.link(keg, os.path.join(self.site.home, "Applications", "Wget.app"))
        real = b.write(os.path.join(self.site.applications, "Real.app", "Contents", "Info.plist"))
        other = b.link(self.site.path("elsewhere"), os.path.join(self.site.applications, "Other.app"))
        self.run_phase(inst)
        self.assertFalse(os.path.lexists(system_link))
        self.assertFalse(os.path.lexists(user_link))
        self.assertTrue(os.path.isfile(real))
        self.assertTrue(os.path.lexists(other))

    def test_unremovable_path_removed_under_sudo(self):
        inst = self.site.homebrew()
        cellar = os.path.join(inst.prefix, "Cellar")
        self.fake.rm_fail = {cellar}
        self.run_phase(inst)
        tries = [sudo for sudo, argv in self.fake.ran(rm.RM) if cellar in argv]
        self.assertEqual(tries, [False, True])
        self.assertFalse(os.path.lexists(cellar))
        self.assertIn(f"6.delete.{state.slug(cellar)}.sudo", [e.get("action_id") for e in self.site.journal()])


class CachesTest(HomebrewTest):
    """The caches Homebrew instances share: deleted without a survivor, kept with one, reported when set elsewhere"""

    def caches(self):
        """Fill the four shared Homebrew caches with a file each

        @returns  the cache directories
        """
        home = self.site.home
        paths = [os.path.join(home, "Library", "Caches", "Homebrew"), os.path.join(home, "Library", "Logs", "Homebrew"),
                 os.path.join(self.site.library, "Caches", "Homebrew"), os.path.join(home, ".cache", "Homebrew")]
        for path in paths:
            b.write(os.path.join(path, "x"))
        return paths

    def test_shared_caches_go_without_a_survivor(self):
        inst = self.site.homebrew()
        paths = self.caches()
        self.run_phase(inst)
        for path in paths:
            self.assertFalse(os.path.lexists(path), path)

    def test_shared_caches_stay_with_a_survivor(self):
        other = self.site.homebrew("opt/homebrew2")
        inst = self.site.homebrew()
        paths = self.caches()
        lines = self.run_phase(inst, others=[other])
        for path in paths:
            self.assertTrue(os.path.isdir(path), path)
        self.assertIn(f"  Homebrew's download folders stay: Homebrew at {other.prefix} uses them.", lines)
        self.assertTrue(os.path.isfile(os.path.join(other.prefix, "bin", "brew")))

    def test_moved_cache_directory_is_reported_and_kept(self):
        custom = b.write(os.path.join(self.site.path("mycache"), "x"))
        inst = self.site.homebrew(cache_dir=os.path.dirname(custom))
        lines = self.run_phase(inst)
        self.assertTrue(os.path.isfile(custom))
        self.assertIn(f"  {os.path.dirname(custom)} stays: it is the download folder you set with HOMEBREW_CACHE.",
                      lines)


class ServicesTest(HomebrewTest):
    """The services of a Homebrew instance: owned jobs booted out and deleted, users' own jobs listed"""

    def test_owned_plist_booted_out_then_deleted(self):
        inst = self.site.homebrew()
        label = "homebrew.mxcl.old"
        program = os.path.join(inst.prefix, "opt", "old", "bin", "old")
        plist = b.write_plist(os.path.join(self.site.home, "Library", "LaunchAgents", label + ".plist"), label, program)
        svc = b.service(label, plist, inst.prefix, "old", domain="gui/501", loaded=True, program=program)
        self.fake.jobs[("gui/501", label)] = [b.printed("gui/501", label, plist, program)]
        self.run_phase(inst, [svc])
        bootout = self.fake.index(b.LAUNCHCTL, "bootout", "gui/501/" + label)
        self.assertFalse(self.fake.commands[bootout][0])
        self.assertLess(self.last_tar(), bootout)
        delete = self.fake.index(rm.RM, plist)
        self.assertFalse(self.fake.commands[delete][0])
        self.assertFalse(os.path.lexists(plist))

    def test_unstoppable_job_stops_the_phase(self):
        inst = self.site.homebrew()
        label = "homebrew.mxcl.old"
        program = os.path.join(inst.prefix, "opt", "old", "bin", "old")
        plist = b.write_plist(os.path.join(self.site.home, "Library", "LaunchAgents", label + ".plist"), label, program,
                              ExitTimeOut=2)
        svc = b.service(label, plist, inst.prefix, "old", domain="gui/501", loaded=True, pid=77, program=program,
                        exit_timeout_s=2)
        running = b.printed("gui/501", label, plist, program, pid=77)
        self.fake.jobs[("gui/501", label)] = [running] * 40
        original = self.fake.launchctl

        def stubborn(argv, sudo):
            if argv[1] == "bootout":
                return r.FakeResponse(exit=36)
            return original(argv, sudo)
        with mock.patch.object(self.fake, "launchctl", stubborn), self.assertRaises(rm.Stopped) as cm:
            self.run_phase(inst, [svc])
        self.assertIn(f"did not stop within 12 s; nothing of {inst.prefix} is deleted while it runs: stop it yourself, "
                      "or quit what keeps it running", str(cm.exception))
        self.assertEqual(self.fake.removed(), [])
        self.assertTrue(os.path.isfile(plist))

    def test_user_job_listed_as_will_stop_working(self):
        inst = self.site.homebrew()
        mine = b.write_plist(os.path.join(self.site.home, "Library", "LaunchAgents", "local.mine.plist"), "local.mine",
                             os.path.join(inst.prefix, "bin", "wget"))
        job = b.service("local.mine", mine, inst.prefix, owned=False, program=os.path.join(inst.prefix, "bin", "wget"))
        lines = self.run_phase(inst, [job])
        self.assertIn(f"  Your own service file ~/Library/LaunchAgents/local.mine.plist runs {inst.prefix}/bin/wget, "
                      "which is gone: edit or delete it.", lines)
        self.assertTrue(os.path.isfile(mine))


class CasksTest(HomebrewTest):
    """The cask apps of an undrivable instance, listed for the Trash unless the target adopted the cask"""

    def test_undrivable_cask_apps_listed_for_trash(self):
        inst = self.site.homebrew(drivable=False)
        p = inst.prefix
        trash_app = self.site.cask(inst, "foo", "Foo.app")
        adopted_app = self.site.cask(inst, "bar", "Bar.app")
        adopted = model.Mapping(source=make_package("bar", kind="cask", prefix=p), target_kind="cask",
                                target_name="bar", target_version="1.0", confidence=Confidence.EXACT, evidence=[],
                                companions=[], selections=[], variants_note=None, adopt=True)
        lines = self.run_phase(inst, mappings=[adopted],
                               path_removed={p: [("cask-adopted", "bar"), ("cask", "foo"), ("formula", "wget")]})
        self.assertIn(f"  {trash_app} stays: move the app of the cask foo to the Trash yourself.", lines)
        self.assertFalse([line for line in lines if "Bar.app" in line])
        self.assertTrue(os.path.isfile(os.path.join(trash_app, "Contents", "Info.plist")))
        self.assertTrue(os.path.isfile(os.path.join(adopted_app, "Contents", "Info.plist")))
        self.assertFalse(os.path.lexists(os.path.join(p, "Caskroom")))

    def test_a_drivable_instance_lists_no_cask_apps(self):
        inst = self.site.homebrew()
        lines = self.run_phase(inst)
        self.assertFalse([line for line in lines if "Trash" in line])


class PreconditionTest(HomebrewTest):
    """The preconditions that leave a Homebrew prefix in place, and the formula left that stops the phase"""

    def test_prefix_without_brew_or_cellar_stays(self):
        inst = self.site.homebrew()
        os.unlink(os.path.join(inst.prefix, "bin", "brew"))
        shutil.rmtree(os.path.join(inst.prefix, "Cellar"))
        lines = self.run_phase(inst)
        self.assertIn(f"  Homebrew at {inst.prefix} stays, untouched: it holds neither bin/brew nor Cellar, so nothing "
                      "shows that it is Homebrew.", lines)
        self.assertEqual(self.fake.commands, [])

    def test_prefix_without_phase_1_snapshot_stays(self):
        inst = self.site.homebrew()
        shutil.rmtree(snapshot.brew_dir(self.site.run_dir, inst.prefix))
        lines = self.run_phase(inst)
        self.assertIn(f"  Homebrew at {inst.prefix} stays, untouched: the record saved for undo lacks all-formulae.txt "
                      "and casks.txt.", lines)
        self.assertEqual(self.fake.commands, [])

    def test_prefix_of_an_unaccepted_origin_stays(self):
        inst = self.site.homebrew(binary=None)
        lines = self.run_phase(inst)
        self.assertTrue([line for line in lines if "is not /opt/homebrew, /usr/local, HOMEBREW_PREFIX" in line])
        self.assertTrue(os.path.isdir(os.path.join(inst.prefix, "Cellar")))

    def test_homebrew_prefix_names_a_prefix_phase_6_accepts(self):
        inst = self.site.homebrew(binary=None)
        self.run_phase(inst, environ={"HOMEBREW_PREFIX": inst.prefix})
        self.assertFalse(os.path.lexists(inst.prefix))

    def test_remaining_formula_stops_the_phase(self):
        inst = self.site.homebrew(formula=True)
        with self.assertRaises(rm.Stopped) as cm:
            self.run_phase(inst)
        self.assertIn("still holds 1 package", str(cm.exception))
        self.assertIn("    Cellar/wget", cm.exception.lines)
        self.assertEqual(self.fake.archived(), [])


if __name__ == "__main__":
    unittest.main()

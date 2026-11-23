"""Phase 7 of `apply`: selections, service starts, interpreter and language notes, and a failed write"""

import os
import unittest

from brew_ports import envclean, exec_env, exec_run, executor, model, snapshot
from tests.unit.fixtures.executor import builders as b
from tests.unit.helpers import make_package
from tests.unit.test_executor import ApplyTest


class Phase7Test(ApplyTest):
    """The parts of phase 7 that `exec_env` computes, and a write that fails"""

    def make_run(self):
        """Return a `Run` of the current plan with its first scan taken

        @returns  the run
        """
        self.ctx = b.context(self.sd)
        run_dir = self.sd.new_run()
        run = exec_run.Run(self.ctx, self.factory(self.ctx, run_dir), run_dir, self.plan, self.plan_path,
                           resumed=False, dry_run=False, stop_after=None)
        run.fresh_scan()
        return run

    def select_files(self, prefix, group, base, option, lines):
        """Write the `base` and option files of a select group

        @param prefix  the MacPorts prefix
        @param group   the select group
        @param base    the lines of `base`
        @param option  the option, which names its file
        @param lines   the lines of the option's file
        """
        directory = os.path.join(prefix, "etc", "select", group)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "base"), "w") as fh:
            fh.write("".join(line + "\n" for line in base))
        with open(os.path.join(directory, option), "w") as fh:
            fh.write("".join(line + "\n" for line in lines))

    def test_selection_needs_every_command_on_path(self):
        target = b.ports_prefix(self.tmp, "opt/local")
        source = b.brew_prefix(self.tmp, "opt/homebrew")
        with open(os.path.join(source, "bin", "python3"), "w"):
            pass
        self.select_files(target, "python3", ["bin/python3", "share/man/man1/python3.1.gz"], "python313",
                          ["bin/python3.13", "-"])
        self.select_files(target, "pip3", ["bin/pip3"], "pip313", ["bin/pip3.13"])
        self.target, self.source = b.ports(target), b.brew(source)
        python = make_package("python@3.13", "formula", source)
        self.host.instances = [self.target, self.source]
        selections = [("python3", "python313"), ("pip3", "pip313"), ("gcc", "mp-gcc14")]
        mapping = b.mapping(python, "port", "python313", version="3.13.1_0", companions=["py313-pip"],
                            selections=selections)
        self.save_plan(b.plan(self.target, [self.source], mappings=[mapping]))
        run = self.make_run()
        executor.record_source_bin(run)
        os.unlink(os.path.join(source, "bin", "python3"))         # phase 5 removed it; the record stays
        actions, reported = exec_env.selections(run)
        self.assertEqual([(a.action_id, a.argv[-4:], a.sudo) for a in actions],
                         [("7.select.python3", ["select", "--set", "python3", "python313"], True)])
        self.assertEqual(actions[0].on_failure, model.OnFailure.PROBE)
        self.assertEqual(reported, [
            f"pip313 is not made the default `pip3`, because {source} did not provide pip3 either. To do it yourself: "
            "sudo port select --set pip3 pip313",
            f"mp-gcc14 is not made the default `gcc`: MacPorts at {target} offers no such choice."])

    def test_a_dry_run_lists_the_selections_without_judging_them(self):
        target = b.ports_prefix(self.tmp, "opt/local")
        source = b.brew_prefix(self.tmp, "opt/homebrew")
        self.target, self.source = b.ports(target), b.brew(source)
        self.host.instances = [self.target, self.source]
        mapping = b.mapping(make_package("python@3.13", "formula", source), "port", "python313", version="3.13.1_0",
                            selections=[("python3", "python313")])
        self.save_plan(b.plan(self.target, [self.source], mappings=[mapping]))
        self.assertEqual(self.apply(dry_run=True), executor.EXIT_OK, self.out)
        self.assertIn(f"  sudo {self.target.binary} -N select --set python3 python313\n"
                      "  A default is set only where the old installation provided the same commands.\n", self.out)
        self.assertNotIn("is not made the default", self.out)

    def test_start_services_starts_the_replacements(self):
        self.scenario_brew()
        prefix = self.source.prefix
        redis = make_package("redis", "port", prefix)
        self.save_plan(b.plan(self.target, [self.source],
                              mappings=self.mappings + [b.mapping(redis, "formula", "redis")],
                              removal={prefix: self.removal[prefix] + [("port", "redis"), ("port", "memcached")]},
                              start_services=True))
        run = self.make_run()
        services = [b.service("org.macports.dnsmasq", self.plist, prefix, "dnsmasq", "port"),
                    b.service("org.macports.redis", "/x/redis.plist", prefix, "redis", "port", scope="user"),
                    b.service("org.macports.memcached", "/x/m.plist", prefix, "memcached", "port",
                              loaded=False)]
        path = os.path.join(snapshot.ports_dir(run.run_dir, prefix), snapshot.SERVICES)
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as fh:
            fh.write(model.to_json(services))
        actions, manual = exec_env.starts(run)
        self.assertEqual([(a.action_id, a.argv[-3:], a.sudo) for a in actions],
                         [("7.start.sh.brew.redis", ["services", "start", "redis"], False)])
        self.assertEqual(manual, ["Start the system service of dnsmasq yourself, because that runs Homebrew as root: "
                                  "sudo brew services start dnsmasq"])

    def test_interpreter_and_language_notes(self):
        self.scenario_brew()
        catalogue = self.host.catalogues[self.target.prefix]
        catalogue.versions.update({"python@3.13": "3.13.1", "python@3.12": "3.12.8"})
        catalogue.aliases["python"] = "python@3.13"
        catalogue.exes["python@3.12"] = ["python3.12", "pip3.12", "idle3"]
        python = make_package("python312", "port", self.source.prefix)
        pip = make_package("py312-pip", "port", self.source.prefix)
        numpy = make_package("py312-numpy", "port", self.source.prefix)
        lang = b.mapping(numpy, "pip", "numpy")
        lang.evidence = ["language package: see language-pip.txt"]
        self.save_plan(b.plan(self.target, [self.source],
                              mappings=[b.mapping(python, "formula", "python@3.12", version="3.12.8"),
                                        b.mapping(pip, "formula", "python@3.12", version="3.12.8")],
                              unmigratable=[lang]))
        run = self.make_run()
        # Two packages become python@3.12: its note is given once.
        self.assertEqual(exec_env.interpreter_notes(run), [
            "python@3.12 does not provide plain `python`: that name belongs to python@3.13. Use python3.12 and "
            f"pip3.12, or the commands in {self.target.prefix}/opt/python@3.12/bin.",
            "1 language package did not move, as the plan said: py312-numpy"])

    def test_failed_write_exits_4(self):
        self.scenario_brew()
        edit = envclean.Edit(path="/Users/alice/.zprofile", kind="rc", old_text="a\n", new_text="b\n", diff="")
        self.modules["brew_ports.envclean"] = b.envclean_module([edit], failed=[edit.path])
        self.assertEqual(self.apply(), executor.EXIT_ACTION)
        self.assertTrue(self.out.endswith("brew-ports: phase 7 did not finish\n"
                                          "    ~/.zprofile could not be written\n"
                                          f"  Continue with: brew-ports apply --resume {self.run_dir.run_id}\n"),
                        self.out)
        self.assertNotIn((7, "7.complete"), self.results())
        self.assertEqual(self.results()[(5, "5.complete")], "ok")

    def test_hand_tasks_are_said_once_when_the_run_ends(self):
        self.scenario_brew()
        manual = envclean.Edit(path="/Users/alice/.bash_profile", kind="rc", old_text="a\n", new_text="b\n", diff="",
                               manual="it belongs to root")
        self.modules["brew_ports.envclean"] = b.envclean_module([manual])
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        task = "  Make the change phase 7 showed for ~/.bash_profile, which brew-ports does not edit.\n"
        self.assertIn("\nFor you to do:\n" + task, self.out)
        self.assertEqual(self.out.count(task), 1)

    def test_a_file_the_edit_creates_is_reported_as_created(self):
        self.scenario_brew()
        new = envclean.Edit(path="/Users/alice/.zprofile", kind="rc", old_text=None, new_text="b\n", diff="")
        old = envclean.Edit(path="/Users/alice/.zshrc", kind="rc", old_text="a\n", new_text="b\n", diff="")
        self.modules["brew_ports.envclean"] = b.envclean_module([new, old])
        self.assertEqual(self.apply(), executor.EXIT_OK, self.out)
        self.assertIn("  Created ~/.zprofile.\n  Edited ~/.zshrc; the file as it was is kept in the run folder.\n",
                      self.out)


if __name__ == "__main__":
    unittest.main()

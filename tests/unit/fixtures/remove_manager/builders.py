"""Builders for the phase 6 tests: prefixes shaped like `/opt/local`, `/opt/homebrew` and `/usr/local`

They live in a temporary tree, with a host whose `rm` deletes only inside it, and the plan, bundle and terminal
phase 6 receives.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Sequence
from typing import Any

from brew_ports import model, remove_manager, runner as runner_mod, snapshot, state, system
from brew_ports.env import services as env_services
from brew_ports.model import Manager, Usability
from tests.unit.fixtures.doctor import builders as doctor_builders
from tests.unit.fixtures.envclean import builders as envclean_builders
from tests.unit.fixtures.macports import builders as mp_builders
from tests.unit.helpers import make_instance, write_file

UID = 501
GIB = 1 << 30
SUDO = runner_mod.SUDO
LAUNCHCTL = env_services.LAUNCHCTL
NOT_FOUND = doctor_builders.NOT_FOUND
OK = runner_mod.FakeResponse()
NO_RECORD = runner_mod.FakeResponse(exit=56, stderr="<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n")
NO_RECEIPT = runner_mod.FakeResponse(exit=1, stderr="No receipt for 'org.macports.MacPorts' found at '/'.\n")
service = doctor_builders.service
write_plist = doctor_builders.write_plist
printed = doctor_builders.printed


def write(path: str, text: str = "data\n", mode: int | None = None) -> str:
    """Write a text file, making its directory first; a file holds a line of data unless told otherwise

    @param path  the file
    @param text  its content
    @param mode  its permission bits; None leaves the default
    @returns     the path
    """
    return write_file(path, text, mode)


def link(target: str, path: str) -> str:
    """Make a symlink, making its directory first

    @param target  what the link points to, relative to its directory or absolute
    @param path    the link
    @returns       the link's path
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.symlink(target, path)
    return path


class FakeHost:
    """A FakeRunner responder for phase 6 that fails the test for any program it does not know

    `rm` deletes inside the test's tree and fails the test for any other path; `tar`, `du`, `lsof`, `git`,
    `dscl`, `pkgutil`, `launchctl`, `cp` and `mkdir` answer from the settings below.
    """

    def __init__(self, tmp: str) -> None:
        """Start with a host where every archive and deletion works, no process runs and no receipt exists

        @param tmp  the test's temporary directory, the only tree `rm` may touch
        """
        self.tmp = os.path.realpath(tmp)
        self.lsof = ""                                   # `lsof -F pn` output
        self.lsof_exit = 0
        self.tar_fail: set[str] = set()                  # paths whose archive fails
        self.du_missing: set[str] = set()                # paths du prints no size for
        self.rm_fail: set[str] = set()                   # paths rm cannot remove as the user
        self.rm_fail_root: set[str] = set()              # ... nor as root
        self.git: dict[str, runner_mod.FakeResponse] = {}
        self.homes: dict[str, str] = {}                  # dscl record -> NFSHomeDirectory
        self.receipt: list[str] | None = None          # `pkgutil --files` lines, relative to /
        self.jobs: dict[tuple[str, str], list[runner_mod.FakeResponse]] = {}
        self.commands: list[tuple[bool, tuple[str, ...]]] = []

    def __call__(self, key: tuple[str, ...]) -> runner_mod.FakeResponse:
        """Record one command, its sudo prefix taken off, and answer it with its program's handler

        @param key  the command line
        @returns    the handler's response
        """
        argv = list(key)
        sudo = argv[:2] == [SUDO, "-n"]
        if sudo:
            argv = argv[argv.index("--") + 1:]
        self.commands.append((sudo, tuple(argv)))
        handlers = {remove_manager.RM: self.rm, remove_manager.TAR: self.tar, remove_manager.DU: self.du,
                    remove_manager.LSOF: self.lsof_, remove_manager.GIT: self.git_, remove_manager.DSCL: self.dscl,
                    remove_manager.PKGUTIL: self.pkgutil, LAUNCHCTL: self.launchctl,
                    runner_mod.CP: self.ok, runner_mod.MKDIR: self.ok}
        handler = handlers.get(argv[0])
        if handler is None:
            raise AssertionError(f"phase 6 ran an unexpected program: {key!r}")
        return handler(argv, sudo)

    # The programs --------------------------------------------------------------------------

    def ok(self, _argv: list[str], _sudo: bool) -> runner_mod.FakeResponse:
        """Answer `cp` and `mkdir` with success

        @param _argv  the command line, which the fake ignores
        @param _sudo  whether it runs as root, which the fake ignores
        @returns      exit 0 without output
        """
        return OK

    def inside(self, path: str) -> None:
        """Fail the test unless `path` lies inside the test's tree

        @param path  a path given to `rm`
        """
        real = os.path.realpath(os.path.dirname(path))
        if real != self.tmp and not real.startswith(self.tmp + "/"):
            raise AssertionError(f"rm outside the test's tree: {path}")

    def rm(self, argv: list[str], sudo: bool) -> runner_mod.FakeResponse:
        """Delete paths inside the test's tree as `rm` does, failing those `rm_fail` names

        @param argv  `rm`, its flags and the paths
        @param sudo  whether it runs as root, where a path of `rm_fail` fails only when `rm_fail_root` names it too
        @returns     exit 1 with a permission error when a path stays, else exit 0
        """
        flags, paths = argv[1], argv[2:]
        for path in paths:
            self.inside(path)
        failed = False
        for path in paths:
            if path in self.rm_fail and (not sudo or path in self.rm_fail_root):
                failed = True
                continue
            if not os.path.lexists(path):
                continue
            if flags == "-d":
                try:
                    os.rmdir(path)
                except OSError:
                    failed = True
            elif os.path.isdir(path) and not os.path.islink(path):
                if flags != "-rf":
                    failed = True
                    continue
                for dirpath, dirnames, _ in os.walk(path):
                    for name in dirnames:
                        os.chmod(os.path.join(dirpath, name), 0o755)
                shutil.rmtree(path)
            else:
                os.unlink(path)
        return runner_mod.FakeResponse(exit=1 if failed else 0, stderr="rm: Permission denied\n" if failed else "")

    def tar(self, argv: list[str], _sudo: bool) -> runner_mod.FakeResponse:
        """Answer an archive, failing when it holds a path of `tar_fail`

        @param argv   the `tar` command line, its paths relative to `-C /`
        @param _sudo  whether it runs as root, which the fake ignores
        @returns      the archived paths as output, or exit 1
        """
        rels = argv[argv.index("-C") + 2:]
        for rel in rels:
            if "/" + rel in self.tar_fail:
                return runner_mod.FakeResponse(exit=1, stderr=f"tar: {rel}: Cannot open\n")
        return runner_mod.FakeResponse(stdout="".join(f"archived /{rel}\n" for rel in rels))

    def du(self, argv: list[str], _sudo: bool) -> runner_mod.FakeResponse:
        """Answer `du -sk` with the size of each path's files in KiB plus 4, leaving out `du_missing`

        @param argv   the `du` command line, its paths after `-sk`
        @param _sudo  whether it runs as root, which the fake ignores
        @returns      one `<KiB>\\t<path>` line per path
        """
        lines = []
        for path in argv[2:]:
            if path in self.du_missing:
                continue
            total = 0
            for dirpath, _, filenames in os.walk(path):
                for name in filenames:
                    try:
                        total += os.lstat(os.path.join(dirpath, name)).st_size
                    except OSError:
                        pass
            lines.append(f"{total // 1024 + 4}\t{path}\n")
        return runner_mod.FakeResponse(stdout="".join(lines))

    def lsof_(self, _argv: list[str], _sudo: bool) -> runner_mod.FakeResponse:
        """Answer `lsof -F pn` from the `lsof` and `lsof_exit` settings

        @param _argv  the command line, which the fake ignores
        @param _sudo  whether it runs as root, which the fake ignores
        @returns      the settings' output and exit status
        """
        return runner_mod.FakeResponse(exit=self.lsof_exit, stdout=self.lsof)

    def git_(self, argv: list[str], _sudo: bool) -> runner_mod.FakeResponse:
        """Answer a git probe from the `git` setting, else as a repository without local state

        @param argv   the `git` command line, its subcommand after `-C <repo>`
        @param _sudo  whether it runs as root, which the fake ignores
        @returns      the response the setting gives the subcommand; else no change, no local commit and
                      no stash, and exit 128 for another subcommand
        """
        command = argv[argv.index("-C") + 2]
        defaults = {"status": OK, "rev-list": runner_mod.FakeResponse(stdout="0\n"),
                    "rev-parse": runner_mod.FakeResponse(exit=1)}
        return self.git.get(command, defaults.get(command, runner_mod.FakeResponse(exit=128)))

    def dscl(self, argv: list[str], _sudo: bool) -> runner_mod.FakeResponse:
        """Answer a directory record's home from `homes`, and delete a record from it

        @param argv   the `dscl` command line: the node, `-read` or `-delete`, and the record
        @param _sudo  whether it runs as root, which the fake ignores
        @returns      the `NFSHomeDirectory` line, the record-not-found error, or success for a deletion
        """
        verb, record = argv[2], argv[3]
        if verb == "-read":
            if record not in self.homes:
                return NO_RECORD
            return runner_mod.FakeResponse(stdout=f"NFSHomeDirectory: {self.homes[record]}\n")
        if verb == "-delete":
            self.homes.pop(record, None)
            return OK
        raise AssertionError(f"unexpected dscl call: {argv!r}")

    def pkgutil(self, argv: list[str], _sudo: bool) -> runner_mod.FakeResponse:
        """Answer `pkgutil --files` from `receipt`, and `pkgutil --forget` with success

        @param argv   the `pkgutil` command line
        @param _sudo  whether it runs as root, which the fake ignores
        @returns      the receipt's lines; without a receipt, the error pkgutil prints
        """
        if argv[1] == "--files":
            if self.receipt is not None:
                return runner_mod.FakeResponse(stdout="".join(line + "\n" for line in self.receipt))
            return NO_RECEIPT
        if argv[1] == "--forget":
            return runner_mod.FakeResponse(stdout="Forgetting package 'org.macports.MacPorts' on '/'...\n")
        raise AssertionError(f"unexpected pkgutil call: {argv!r}")

    def launchctl(self, argv: list[str], _sudo: bool) -> runner_mod.FakeResponse:
        """Answer `launchctl print` from the queue `jobs` keeps for a job, which `bootout` empties

        @param argv   the `launchctl` command line
        @param _sudo  whether it runs as root, which the fake ignores
        @returns      the next queued response of `print`, else not found; success for `bootout` and `bootstrap`
        """
        if argv[1] == "print":
            domain, _, label = argv[2].rpartition("/")
            queue = self.jobs.get((domain, label)) or []
            return queue.pop(0) if queue else NOT_FOUND
        if argv[1] == "bootout":
            domain, _, label = argv[2].rpartition("/")
            self.jobs[(domain, label)] = []
            return OK
        if argv[1] == "bootstrap":
            return OK
        raise AssertionError(f"unexpected launchctl call: {argv!r}")

    # Queries for the assertions -----------------------------------------------------------------

    def ran(self, program: str) -> list[tuple[bool, tuple[str, ...]]]:
        """Return the commands of one program, in order

        @param program  the program's path
        @returns        whether each ran as root, and its command line without the sudo prefix
        """
        return [(sudo, argv) for sudo, argv in self.commands if argv[0] == program]

    def removed(self) -> list[str]:
        """Return every path given to `rm`, in order

        @returns  the paths
        """
        return [p for _, argv in self.ran(remove_manager.RM) for p in argv[2:]]

    def archived(self) -> list[list[str]]:
        """Return the absolute paths of each `tar` call

        @returns  one list of paths per call, in order
        """
        out = []
        for _, argv in self.ran(remove_manager.TAR):
            out.append(["/" + rel for rel in argv[list(argv).index("-C") + 2:]])
        return out

    def index(self, program: str, *words: str) -> int:
        """Return the position of the first command of `program` holding all `words`, failing the test without one

        @param program  the program's path
        @param words    words the command line holds, anywhere
        @returns        the position in `commands`
        """
        for number, (_, argv) in enumerate(self.commands):
            if argv[0] == program and all(w in argv for w in words):
                return number
        raise AssertionError(f"{program} {' '.join(words)} never ran")


class Ask:
    """The terminal of `Context` as phase 6 uses it; the questions asked are kept"""

    def __init__(self, answers: Sequence[bool] = (), yes: bool = False, tty: bool = True) -> None:
        """Set up the answers the terminal gives

        @param answers  the answers to `confirm`, in order; the default answers once they run out
        @param yes      the `--yes` flag
        @param tty      whether a terminal is attached
        """
        self.answers = list(answers)
        self.yes = yes
        self.tty = tty
        self.asked: list[str] = []

    def confirm(self, question: str, default: bool = False) -> bool:
        """Keep a question and give the next answer

        @param question  the question
        @param default   the answer once the answers run out
        @returns         the answer
        """
        self.asked.append(question)
        return self.answers.pop(0) if self.answers else default

    def confirm_terminal(self, question: str) -> bool:
        """Keep a question asked on the terminal, and decline it

        @param question  the question
        @returns         False
        """
        self.asked.append(question)
        return False


class Site:
    """A temporary host for one phase 6 test, with the instances it builds

    It holds a home, a run directory, and stand-ins for `/Applications`, `/Library`, `/etc/paths.d` and
    `/usr/local`.
    """

    def __init__(self, tmp: str) -> None:
        """Make the host's directories, its state directory and run, and its fake commands

        @param tmp  the test's temporary directory
        """
        self.tmp = tmp
        self.home = self.mkdir("Users", "alice")
        self.applications = self.mkdir("Applications")
        self.library = self.mkdir("Library")
        for sub in ("LaunchDaemons", "LaunchAgents"):
            self.mkdir("Library", sub)
        self.etc_paths_d = self.mkdir("etc", "paths.d")
        self.usr_local = os.path.join(tmp, "usr", "local")
        self.state = state.StateDir(os.path.join(tmp, "state"))
        self.run_dir = self.state.new_run()
        self.fake = FakeHost(tmp)
        self.free = 100 * GIB
        self.clock = doctor_builders.FakeClock()
        self.quiet = False               # whether the phase runs under `--quiet`
        self.runner: runner_mod.FakeRunner | None = None

    def mkdir(self, *parts: str) -> str:
        """Make a directory below the temporary directory

        @param parts  its path's components
        @returns      the directory's path
        """
        path = os.path.join(self.tmp, *parts)
        os.makedirs(path, exist_ok=True)
        return path

    def path(self, *parts: str) -> str:
        """Return a path below the temporary directory, which need not exist

        @param parts  its components
        @returns      the path
        """
        return os.path.join(self.tmp, *parts)

    # Instances ----------------------------------------------------------------------------------

    def macports(self, rel: str = "opt/local", *, drivable: bool = True, apps: str | None = None,
                 portdbpath: str | None = None, **kw: Any) -> model.Instance:
        """Make a MacPorts prefix with base's files, an empty live registry, and its instance

        @param rel         the prefix below the temporary directory, with `/` separators
        @param drivable    whether the instance can be driven
        @param apps        its `applications_dir`; None for `Applications/MacPorts`
        @param portdbpath  its registry directory, which the caller fills; None for `<prefix>/var/macports`
                           with an empty registry
        @param kw          further fields of the instance
        @returns           the instance
        """
        prefix = self.path(*rel.split("/"))
        apps_dir = apps if apps is not None else os.path.join(self.applications, "MacPorts")
        db = portdbpath or os.path.join(prefix, "var", "macports")
        mp_builders.make_prefix(prefix, conf={"prefix": prefix, "portdbpath": db, "applications_dir": apps_dir})
        if portdbpath is None:
            mp_builders.make_registry(db)
        values: dict[str, Any] = {"identity": system.identity(prefix), "spellings": (prefix,), "portdbpath": db,
                                  "applications_dir": apps_dir, "owned_roots": (prefix,), "drivable": drivable,
                                  "usability": Usability.USABLE if drivable else Usability.CANNOT_RUN}
        values.update(kw)
        return make_instance(Manager.PORTS, prefix, **values)

    def phase1_registry(self, inst: model.Instance, ports: Sequence[dict[str, Any]] = (),
                        files: Sequence[Sequence[Any]] = ()) -> str:
        """Write the phase 1 registry backup of a MacPorts instance under `<run>/snapshot/`

        @param inst   the MacPorts instance
        @param ports  the `ports` rows, as `mp_builders.port` builds them
        @param files  the `files` rows, `(id, path, actual_path, active, binary)` tuples
        @returns      the path of the backup's `registry.db`
        """
        return mp_builders.make_registry(snapshot.ports_dir(self.run_dir, inst.prefix), ports=ports, files=files)

    def homebrew(self, rel: str = "opt/homebrew", *, drivable: bool = True, usr_local: bool = False,
                 formula: bool | None = None, **kw: Any) -> model.Instance:
        """Make a Homebrew prefix with its repository, data in `var` and `etc`, its phase 1 snapshot and instance

        At `/usr/local` the repository is `Homebrew/` and the owned roots are Homebrew's five subtrees.

        @param rel        the prefix below the temporary directory, with `/` separators
        @param drivable   whether the instance can be driven
        @param usr_local  whether the prefix is the host's `/usr/local` stand-in, which `rel` then does not name
        @param formula    whether to add one formula linked into `bin`, `opt` and `share`; None adds it to an
                          undrivable instance, whose packages phase 5 cannot remove
        @param kw         further fields of the instance
        @returns          the instance
        """
        prefix = self.usr_local if usr_local else self.path(*rel.split("/"))
        repo = os.path.join(prefix, "Homebrew") if usr_local else prefix
        write(os.path.join(repo, "Library", "Homebrew", "brew.sh"), "# brew\n")
        write(os.path.join(repo, ".git", "HEAD"), "ref: refs/heads/main\n")
        write(os.path.join(repo, "README.md"), "# Homebrew\n")
        write(os.path.join(repo, "bin", "brew"), "#!/bin/bash\n", 0o755)
        if usr_local:
            link("../Homebrew/bin/brew", os.path.join(prefix, "bin", "brew"))
        os.makedirs(os.path.join(prefix, "Cellar"), exist_ok=True)
        if formula if formula is not None else not drivable:
            keg = os.path.join(prefix, "Cellar", "wget", "1.25.0")
            write(os.path.join(keg, "bin", "wget"), "#!/bin/sh\n", 0o755)
            write(os.path.join(keg, "share", "man", "man1", "wget.1"), ".TH WGET 1\n")
            write(os.path.join(keg, "INSTALL_RECEIPT.json"), "{}\n")
            link("../Cellar/wget/1.25.0", os.path.join(prefix, "opt", "wget"))
            link("../Cellar/wget/1.25.0/bin/wget", os.path.join(prefix, "bin", "wget"))
            link("../../../Cellar/wget/1.25.0/share/man/man1/wget.1",
                 os.path.join(prefix, "share", "man", "man1", "wget.1"))
        write(os.path.join(prefix, "var", "homebrew", "linked", ".keep"), "")
        write(os.path.join(prefix, "var", "log", "wget.log"), "log\n")
        write(os.path.join(prefix, "etc", "wgetrc"), "# wgetrc\n")
        os.makedirs(os.path.join(prefix, "Caskroom"), exist_ok=True)
        roots = tuple(os.path.join(prefix, r) for r in envclean_builders.USR_LOCAL_ROOTS) if usr_local else (prefix,)
        values: dict[str, Any] = {"identity": system.identity(prefix), "spellings": (prefix,), "repository": repo,
                                  "owned_roots": roots, "drivable": drivable,
                                  "usability": Usability.USABLE if drivable else Usability.CANNOT_RUN,
                                  "cache_dir": os.path.join(self.home, "Library", "Caches", "Homebrew")}
        values.update(kw)
        inst = make_instance(Manager.BREW, prefix, **values)
        self.phase1_homebrew(inst)
        return inst

    def phase1_homebrew(self, inst: model.Instance) -> None:
        """Write the phase 1 disk snapshot of a Homebrew instance: formula and cask lists without packages

        @param inst  the Homebrew instance
        """
        directory = snapshot.brew_dir(self.run_dir, inst.prefix)
        write(os.path.join(directory, snapshot.FORMULAE), snapshot.FORMULAE_HEADER + "\n")
        write(os.path.join(directory, snapshot.CASKS), snapshot.CASKS_HEADER + "\n")

    def target_homebrew(self) -> model.Instance:
        """Make the `opt/homebrew` prefix a plan targets

        @returns  its instance
        """
        prefix = self.mkdir("opt", "homebrew")
        return make_instance(Manager.BREW, prefix, identity=system.identity(prefix), spellings=(prefix,),
                             owned_roots=(prefix,))

    def target_macports(self, rel: str = "opt/local") -> model.Instance:
        """Make the MacPorts prefix a plan targets

        @param rel  the prefix below the temporary directory, with `/` separators
        @returns    its instance
        """
        return self.macports(rel)

    def cask(self, inst: model.Instance, token: str, app: str, *, appdir: str | None = None) -> str:
        """Write a Caskroom entry whose receipt lists one `app` artifact, and the app bundle

        The entry's `config.json` names the app directory.

        @param inst    the Homebrew instance
        @param token   the cask
        @param app     the bundle's name, such as `Foo.app`
        @param appdir  the app directory; None for the host's `/Applications` stand-in
        @returns       the bundle's path
        """
        room = os.path.join(inst.prefix, "Caskroom", token)
        os.makedirs(os.path.join(room, "1.0"), exist_ok=True)
        os.makedirs(os.path.join(room, ".metadata", "1.0", "20261101000000.000"), exist_ok=True)
        write(os.path.join(room, ".metadata", "INSTALL_RECEIPT.json"),
              json.dumps({"uninstall_artifacts": [{"app": [app]}, {"zap": [{"trash": ["~/Library/x"]}]}]}))
        target_dir = appdir or self.applications
        write(os.path.join(room, ".metadata", "config.json"), json.dumps({"explicit": {"appdir": target_dir}}))
        bundle_dir = os.path.join(target_dir, app)
        write(os.path.join(bundle_dir, "Contents", "Info.plist"), "<plist/>\n")
        return bundle_dir

    # The call ------------------------------------------------------------------------------------

    def bundle(self, instances: Sequence[model.Instance], services: Sequence[model.Service] = (),
               packages: Sequence[model.Package] = ()):
        """Build the scan bundle phase 6 receives, with the user's uid and home

        @param instances  the instances on the host
        @param services   the services the scan found
        @param packages   the packages the scan found
        @returns          the bundle
        """
        return doctor_builders.bundle(instances=instances, packages=packages, services=services,
                                      system={"uid": UID, "home": self.home})

    def plan(self, target: model.Instance, instances: Sequence[model.Instance], named: Sequence[model.Instance],
             **kw: Any) -> model.Plan:
        """Build a plan of this run whose `remove_manager` option names instances

        @param target     the plan's target
        @param instances  every instance of the plan
        @param named      the instances phase 6 removes, in order
        @param kw         further fields of the plan
        @returns          the plan
        """
        options = {"remove_manager": ",".join(i.prefix for i in named)}
        return envclean_builders.plan(target, instances, options=options, run_id=self.run_dir.run_id, **kw)

    def host(self) -> remove_manager.Host:
        """Return the host's stand-in locations and clocks for `remove_manager.run`

        @returns  the host, its volume `free` bytes free and no process alive
        """
        return remove_manager.Host(usr_local=self.usr_local, applications=self.applications, library=self.library,
                                   etc_paths_d=self.etc_paths_d, free_bytes=lambda path: self.free,
                                   clock=self.clock, sleep=self.clock.sleep, alive=lambda pid: False)

    def run(self, plan: model.Plan, bundle, ask: Ask | None = None, resumed: bool = False,
            environ: dict[str, str] | None = None) -> list[str]:
        """Run phase 6 with a FakeRunner over the fake host

        @param plan     the plan
        @param bundle   the scan bundle
        @param ask      the terminal; None answers yes to everything
        @param resumed  read the run's earlier phase 6 records
        @param environ  variables added to the user's environment
        @returns        the report lines
        """
        env_vars = {"HOME": self.home, "USER": "alice"}
        env_vars.update(environ or {})
        console = doctor_builders.QuietConsole()
        console.quiet = self.quiet
        self.runner = runner_mod.FakeRunner(default=self.fake, console=console, environ=env_vars,
                                            run_dir=self.run_dir)
        return remove_manager.run(self.runner, self.run_dir, plan, bundle, ask or Ask(yes=True), resumed=resumed,
                                  host=self.host())

    def journal(self) -> list[dict[str, Any]]:
        """Return the run's journal entries

        @returns  the entries, in order
        """
        return self.run_dir.journal.entries()

    def archive(self, path: str) -> str:
        """Return where phase 6 stores the archive of a path

        @param path  the archived path
        @returns     the file `<run>/data-archive/<slug>.tar.gz`
        """
        return os.path.join(self.run_dir.path, remove_manager.ARCHIVES, state.slug(path) + ".tar.gz")


def lsof_output(processes: Sequence[tuple[int, Sequence[tuple[str, str]]]]) -> str:
    """Format `lsof -F pn` text: `p<pid>`, then `f<descriptor>` and `n<name>` per file

    @param processes  each PID with its files, `(descriptor, name)` pairs
    @returns          the text
    """
    lines = []
    for pid, files in processes:
        lines.append(f"p{pid}")
        for fd, name in files:
            lines += ["f" + fd, "n" + name]
    return "\n".join(lines) + "\n"

"""Builders for the env-cleanup tests: instances, scan bundles, plans, a fake syntax checker and root-file store"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Sequence
from typing import Any

from brew_ports import model, runner as runner_mod, state, system
from brew_ports.model import Manager
from tests.unit.fixtures.doctor import builders as doctor_builders
from tests.unit.helpers import make_instance, make_package

USR_LOCAL_ROOTS = ("Cellar", "Caskroom", "Homebrew", "opt", os.path.join("var", "homebrew"))
QuietConsole = doctor_builders.QuietConsole
CHECKERS = ("/bin/zsh", "/bin/bash", "/bin/sh", "/bin/tcsh")


def instance(tmp: str, manager: Manager, rel: str, *, roots: Sequence[str] | None = None, exists: bool = True,
             **kw: Any) -> model.Instance:
    """Return an instance at `<tmp>/<rel>` whose owned roots are `roots` below the prefix, else the prefix

    `exists=False` leaves the prefix absent, as after phase 6 deleted it.

    @param tmp      the test's temporary directory
    @param manager  Homebrew or MacPorts
    @param rel      the prefix below `tmp`, with `/` separators
    @param roots    the owned roots, relative to the prefix; None for the prefix itself
    @param exists   whether to make the prefix, its owned roots, `bin` and `sbin`
    @param kw       further fields for `make_instance`; `identity` and `spellings` default to the prefix's
    @returns        the instance, as `make_instance` builds it
    """
    prefix = os.path.join(tmp, *rel.split("/"))
    owned = (prefix,) if roots is None else tuple(os.path.join(prefix, r) for r in roots)
    if exists:
        os.makedirs(prefix, exist_ok=True)
        for root in owned:
            os.makedirs(root, exist_ok=True)
        for sub in ("bin", "sbin"):
            os.makedirs(os.path.join(prefix, sub), exist_ok=True)
    kw.setdefault("identity", system.identity(prefix) or (0, 0))
    kw.setdefault("spellings", (prefix,))
    return make_instance(manager, prefix, owned_roots=owned, **kw)


def package(inst: model.Instance, name: str = "wget", **kw: Any) -> model.Package:
    """Return a package of an instance: a port in MacPorts, else a formula

    @param inst  the instance that holds the package
    @param name  the package's name
    @param kw    further fields for `make_package`; `kind` overrides the default kind
    @returns     the package, as `make_package` builds it
    """
    kind = "port" if inst.manager is Manager.PORTS else "formula"
    return make_package(name, kind=kw.pop("kind", kind), prefix=inst.prefix, **kw)


def bundle(instances: Sequence[model.Instance], packages: Sequence[model.Package] = (), *,
           login_shell: str | None = None, gui: Sequence[str] | None = None,
           live_path: Sequence[Any] = ()):
    """Return a scan bundle without a shell analysis, whose environment holds the login shell and the paths

    @param instances    the instances the scan found
    @param packages     the packages the scan found
    @param login_shell  the account's login shell, or None
    @param gui          the entries of the GUI PATH; None for no GUI PATH
    @param live_path    the live PATH, as `(text, instance prefix)` pairs
    @returns            the bundle, as the doctor fixtures build it
    """
    environment = {"login_shell": login_shell,
                   "gui_path": [{"text": t} for t in gui] if gui is not None else None,
                   "live": {"PATH": [{"text": t, "instance_prefix": p} for t, p in live_path]}}
    return doctor_builders.bundle(instances=instances, packages=packages, environment=environment)


def plan(target: model.Instance, instances: Sequence[model.Instance], *, options: dict[str, str] | None = None,
         run_id: str = "", **kw: Any) -> model.Plan:
    """Return a plan without phases that migrates the other instances into the target

    @param target     the target instance
    @param instances  the instances the plan records; every one but the target is a source
    @param options    the plan's options, such as `only`; None for none
    @param run_id     the id of the run that holds the plan
    @param kw         further fields of the plan, which override these
    @returns          the plan
    """
    values: dict[str, Any] = {
        "created": "2026-11-13T10:00:00+1100", "run_id": run_id, "target": target.manager, "instances": list(instances),
        "source_prefixes": [i.prefix for i in instances if i.prefix != target.prefix], "target_prefix": target.prefix,
        "roots": [], "kept": [], "left_in_place": [], "mappings": [], "unmigratable": [], "removal_set": {},
        "path_removed": {}, "manual_casks": [], "target_upgrades": [], "phases": [], "options": dict(options or {})}
    values.update(kw)
    return model.Plan(**values)


def write_run(state_dir: state.StateDir, run_id: str, the_plan: model.Plan | None,
              journal: Sequence[dict[str, Any]] = ()) -> state.RunDir:
    """Write a run directory with its `plan.json` and journal lines

    @param state_dir  the state directory that holds the run
    @param run_id     the run's id, the name of its directory
    @param the_plan   the plan to write; None for a run without one
    @param journal    the journal entries, in order
    @returns          the run directory
    """
    path = os.path.join(state_dir.runs, run_id)
    os.makedirs(path)
    run_dir = state.RunDir(path)
    if the_plan is not None:
        run_dir.write_json("plan.json", model.to_json(the_plan))
    for entry in journal:
        run_dir.journal.append(dict(entry))
    return run_dir


def malform_plan(path: str) -> None:
    """Rewrite a `plan.json` with a list where its `options` dict goes, which `model.from_json` rejects

    @param path  the plan file
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data["options"] = []
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


_THEN = re.compile(r"(?:^|[;\s])(?:then|do|else)\s*$")
_CLOSE = re.compile(r"^\s*(?:fi|done|else|elif\b)")


def empty_branch(text: str) -> bool:
    """Return whether `text` has a branch without a command, which bash rejects

    @param text  a shell file's text
    @returns     True when a line ending in `then`, `do` or `else` is followed by `fi`, `done`, `else` or `elif`
    """
    code = [line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    return any(_THEN.search(a) and _CLOSE.match(b) for a, b in zip(code, code[1:]))


def syntax_responder(reject: Callable[[str], bool] = empty_branch, other: Callable | None = None,
                     calls: list[str] | None = None):
    """Return a FakeRunner responder whose shell `-n` checks fail when `reject` says so

    Every other command goes to `other`, else exits 0.

    @param reject  returns whether a checked text is a syntax error
    @param other   answers every other command; None exits 0
    @param calls   receives each text checked, in order; None keeps no record
    @returns       the responder
    """

    def respond(key):
        if key[0] in CHECKERS:
            with open(key[-1], encoding="utf-8") as fh:
                text = fh.read()
            if calls is not None:
                calls.append(text)
            if reject(text):
                return runner_mod.FakeResponse(exit=2, stderr=f"{key[-1]}: syntax error\n")
            return runner_mod.FakeResponse()
        return other(key) if other is not None else runner_mod.FakeResponse()
    return respond


def fake_runner(run_dir: state.RunDir | None, responder=None, environ: dict[str, str] | None = None,
                out_dir: str | None = None) -> runner_mod.FakeRunner:
    """Return a quiet fake runner whose default responder answers the syntax checks

    @param run_dir    receives the journal and the output files; None keeps no record
    @param responder  the default responder; None for `syntax_responder()`
    @param environ    the environment; None for a `HOME` of `/Users/alice`
    @param out_dir    the directory of the output files; None for the runner's default
    @returns          the runner
    """
    return runner_mod.FakeRunner(default=responder or syntax_responder(), console=QuietConsole(),
                                 environ=environ or {"HOME": "/Users/alice"}, run_dir=run_dir, out_dir=out_dir)


def console_text(fake: runner_mod.FakeRunner) -> str:
    """Return what a runner from `fake_runner` printed

    @param fake  the runner, whose console is a QuietConsole
    @returns     the text its console holds
    """
    console = fake.console
    if not isinstance(console, QuietConsole):
        raise TypeError(f"the runner prints to a {type(console).__name__}, not to a QuietConsole")
    return console.text


class FakeRootFiles(runner_mod.RootFiles):
    """`runner.RootFiles` as the tests see it: the files it writes and backs up, and whether its staging goes"""

    def __init__(self, runner: runner_mod.BaseRunner) -> None:
        """Start with no write, no backup and the staging in place

        @param runner  the runner of the test, which the fake never uses
        """
        super().__init__(runner, "test")
        self.writes: list[tuple] = []
        self.backups: list[str] = []
        self.staging_removed = False

    def write(self, path: str, content: str, tmp_dir: str) -> str:
        """Record a write as root

        @param path     the file
        @param content  its text
        @param tmp_dir  the parent of the staging directory, which the fake never uses
        @returns        the SHA-256 of the content, as `RootFiles.write` returns it
        """
        self.writes.append((path, content))
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def backup(self, path: str) -> str:
        """Record a backup as root

        @param path  the file
        @returns     where the copy would be kept
        """
        self.backups.append(path)
        return f"/private/var/db/brew-ports/run/{state.slug(path)}"

    def remove_staging(self) -> None:
        """Record that the staging directory is removed"""
        self.staging_removed = True

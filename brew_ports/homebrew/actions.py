"""Builders for every `brew` command the tool runs

Each runs the instance's own `brew` as the user under the `brew` profile, and none sets `sudo`. Only `config`,
the drivability probe, and `manual`, whose line is never run, take an undrivable instance.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..model import Action, Instance, OnFailure
from ..report import typed
from ..runner import arch_argv, require_names

INVENTORY_TIMEOUT_S = 600   # info, outdated, deps and missing load every installed formula

DOCTOR_CHECKS = (
    "check_deleted_formula", "check_deprecated_disabled", "check_for_unlinked_but_not_keg_only",
    "check_for_broken_symlinks", "check_for_stray_dylibs", "check_for_stray_static_libs",
    "check_for_stray_pcs", "check_for_stray_las", "check_for_stray_headers",
)


def _names(names: Sequence[str]) -> list[str]:
    """Return package names without empty entries, refusing an empty list or a name `brew` would read as an option

    @param names  formula names or cask tokens
    @returns      the names that are not empty, in their order
    """
    names = require_names(names)
    for name in names:
        if name.startswith("-"):
            raise ValueError(f"refusing a package name that starts with '-': {name!r}")
    return names


def _head(instance: Instance, host_arch: str, args: Sequence[str], allow_undrivable: bool = False) -> list[str]:
    """Return `[arch -<arch>] <prefix>/bin/brew <args...>`, the argv of the instance's own binary

    @param instance          the Homebrew instance whose binary the command runs
    @param host_arch         the host's architecture, which decides the `arch` prefix
    @param args              the arguments after the binary
    @param allow_undrivable  build the argv for an instance that is not drivable
    @returns                 the argv, `arch -<arch>` first on an arm64 host
    """
    if not instance.binary:
        raise ValueError(f"{instance.prefix} has no brew binary")
    if not instance.drivable and not allow_undrivable:
        raise ValueError(f"no brew command is built for the undrivable instance {instance.prefix}")
    return arch_argv(instance.arch, host_arch, [instance.binary] + list(args))


def _action(instance: Instance, action_id: str, argv: list[str], description: str, *,
            on_failure: OnFailure = OnFailure.STOP, read_only: bool = False,
            timeout_s: int | None = None, split_order: Sequence[str] | None = None,
            split_head: int = 0, retry_argv: list[str] | None = None) -> Action:
    """Return a `brew` command that runs as the user under the `brew` profile

    @param instance     the Homebrew instance whose binary the command runs
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param argv         the whole command, `arch` and the binary included
    @param description  the text shown for the action
    @param on_failure   what a failure of the command does
    @param read_only    True for a probe that changes nothing
    @param timeout_s    the timeout in seconds; None leaves the runner's default
    @param split_order  SPLIT: the names in retry order
    @param split_head   SPLIT: how many leading argv words form the command before the names
    @param retry_argv   RETRY_WITH: the alternative command
    @returns            the action
    """
    return Action(action_id=action_id, kind="command", argv=argv, sudo=False, description=description,
                  env_profile="brew", on_failure=on_failure, retry_argv=list(retry_argv or []),
                  split_order=list(split_order or []), read_only=read_only, timeout_s=timeout_s,
                  instance_prefix=instance.prefix, split_head=split_head)


def _probe(instance: Instance, host_arch: str, action_id: str, args: Sequence[str], description: str, *,
           timeout_s: int | None = None, allow_undrivable: bool = False) -> Action:
    """Return a read-only `brew` probe, whose exit status is data

    @param instance          the Homebrew instance whose binary the probe runs
    @param host_arch         the host's architecture, which decides the `arch` prefix
    @param action_id         the action's `<phase>.<subject>.<step>` id
    @param args              the arguments after the binary
    @param description       the text shown for the probe
    @param timeout_s         the timeout in seconds; None leaves the runner's default
    @param allow_undrivable  build the probe for an instance that is not drivable
    @returns                 the action
    """
    return _action(instance, action_id, _head(instance, host_arch, args, allow_undrivable), description,
                   on_failure=OnFailure.PROBE, read_only=True, timeout_s=timeout_s)


def _batch(instance: Instance, host_arch: str, action_id: str, args: Sequence[str], names: Sequence[str], *,
           description: str, on_failure: OnFailure, split_order: Sequence[str] | None = None) -> Action:
    """Build one command naming several packages; `SPLIT` retries them one at a time in `split_order`

    @param instance     the Homebrew instance whose binary the command runs
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param args         the subcommand and its options, before the names
    @param names        the formulae or casks the command names
    @param description  the text shown for the action
    @param on_failure   what a failure of the command does
    @param split_order  SPLIT: the retry order, which must hold exactly the names; None keeps their order
    @returns            the action
    """
    names = _names(names)
    head = _head(instance, host_arch, args)
    order = list(split_order) if split_order is not None else list(names)
    if on_failure is OnFailure.SPLIT and sorted(order) != sorted(names):
        raise ValueError(f"split_order of {action_id} must hold exactly the batch's names")
    return _action(instance, action_id, head + names, description, on_failure=on_failure,
                   split_order=order if on_failure is OnFailure.SPLIT else None,
                   split_head=len(head) if on_failure is OnFailure.SPLIT else 0)


# Probes ---------------------------------------------------------------------

def config(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Probe `brew config`, whose exit 0 makes the instance `USABLE`

    Run it only after the Ruby probe passed.

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @returns          the action
    """
    return _probe(instance, host_arch, action_id, ["config"], "Homebrew configuration", allow_undrivable=True)


def cache(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Probe `brew --cache` for the instance's `cache_dir`

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @returns          the action
    """
    return _probe(instance, host_arch, action_id, ["--cache"], "Homebrew download cache")


def info_installed(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Probe `brew info --json=v2 --installed` for every installed formula and cask

    @param instance     the Homebrew instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @returns            the action
    @throws ValueError  the instance has no `brew` binary or is not drivable
    """
    return _probe(instance, host_arch, action_id, ["info", "--json=v2", "--installed"],
                  "installed formulae and casks", timeout_s=INVENTORY_TIMEOUT_S)


def outdated(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Probe `brew outdated --json=v2` for the outdated formulae and casks with their current versions

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @returns          the action
    """
    return _probe(instance, host_arch, action_id, ["outdated", "--json=v2"], "outdated formulae and casks",
                  timeout_s=INVENTORY_TIMEOUT_S)


def deps_installed(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Probe `brew deps --formula --installed --for-each` for each installed formula's dependencies

    `--formula` keeps a cask that shares a formula's name out of its line; cask dependencies come from the
    JSON and the cask receipts.

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @returns          the action
    """
    return _probe(instance, host_arch, action_id, ["deps", "--formula", "--installed", "--for-each"],
                  "dependencies of every installed package", timeout_s=INVENTORY_TIMEOUT_S)


def missing(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Probe `brew missing`, whose report is exit 1 with `<f>: <dep ...>` lines

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @returns          the action
    """
    return _probe(instance, host_arch, action_id, ["missing"], "missing dependencies",
                  timeout_s=INVENTORY_TIMEOUT_S)


def doctor(instance: Instance, host_arch: str, action_id: str, checks: Sequence[str] = DOCTOR_CHECKS) -> Action:
    """Probe `brew doctor <checks...>`, once per instance with every needed check named

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @param checks     the `brew doctor` checks to run, by their method names
    @returns          the action
    """
    return _probe(instance, host_arch, action_id, ["doctor"] + _names(checks), "brew doctor checks")


def services_list(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Probe `brew services list --json`, which only corroborates the tool's own service attribution

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @returns          the action
    """
    return _probe(instance, host_arch, action_id, ["services", "list", "--json"], "Homebrew services")


def bundle_dump(instance: Instance, host_arch: str, action_id: str, path: str) -> Action:
    """Dump the phase 1 `Brewfile`; `--no-restart` keeps `restart_service` out of it

    It loads every installed formula, so it has the inventory probes' timeout.

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @param path       the `Brewfile` to write, replaced when it exists
    @returns          the action
    """
    args = ["bundle", "dump", "--formula", "--cask", "--tap", "--no-restart", "--file=" + path, "--force"]
    return _probe(instance, host_arch, action_id, args, f"Brewfile of {instance.prefix}",
                  timeout_s=INVENTORY_TIMEOUT_S)


# Mutations -----------------------------------------------------------------

def install_formulae(instance: Instance, host_arch: str, action_id: str, names: Sequence[str], *,
                     as_dependency: bool = False, on_failure: OnFailure = OnFailure.SPLIT) -> Action:
    """Install formulae: `brew install --formula [--as-dependency] <names...>`

    Phase 3 installs the bottled and the source-built targets as two such batches.

    @param instance       the Homebrew instance
    @param host_arch      the host's architecture, which decides the `arch` prefix
    @param action_id      the action's `<phase>.<subject>.<step>` id
    @param names          the formulae to install
    @param as_dependency  record them as installed as dependencies, not on request
    @param on_failure     what a failure of the command does
    @returns              the action
    """
    args = ["install", "--formula"] + (["--as-dependency"] if as_dependency else [])
    return _batch(instance, host_arch, action_id, args, names, description="install formulae", on_failure=on_failure)


def install_casks(instance: Instance, host_arch: str, action_id: str, tokens: Sequence[str],
                  on_failure: OnFailure = OnFailure.SPLIT) -> Action:
    """Install casks without `privileged_install`: `brew install --cask <tokens...>`

    @param instance    the Homebrew instance
    @param host_arch   the host's architecture, which decides the `arch` prefix
    @param action_id   the action's `<phase>.<subject>.<step>` id
    @param tokens      the cask tokens to install
    @param on_failure  what a failure of the command does
    @returns           the action
    """
    return _batch(instance, host_arch, action_id, ["install", "--cask"], tokens, description="install casks",
                  on_failure=on_failure)


def adopt_cask(instance: Instance, host_arch: str, action_id: str, token: str) -> Action:
    """Adopt one cask: `brew install --cask --adopt <token>`, retried with `--force`

    The `--force` retry replaces a bundle whose version differs.

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @param token      the cask token
    @returns          the action
    """
    token = _names([token])[0]
    argv = _head(instance, host_arch, ["install", "--cask", "--adopt", token])
    retry = _head(instance, host_arch, ["install", "--cask", "--force", token])
    return _action(instance, action_id, argv, f"adopt the cask {token}", on_failure=OnFailure.RETRY_WITH,
                   retry_argv=retry)


def reinstall(instance: Instance, host_arch: str, action_id: str, names: Sequence[str], *, kind: str = "formula",
              on_failure: OnFailure | None = None) -> Action:
    """Reinstall formulae or casks for a doctor remedy, a phase 3 rebuild or the phase 3 resume

    @param instance     the Homebrew instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param names        the formulae or casks to reinstall
    @param kind         `formula` or `cask`
    @param on_failure   what a failure of the command does; None splits a batch and stops on one name
    @returns            the action
    @throws ValueError  another kind, no usable name, or an instance without a drivable `brew` binary
    """
    names = list(names)
    if kind == "formula":
        args, what = ["reinstall", "--formula"], "formulae"
    elif kind == "cask":
        args, what = ["reinstall", "--cask"], "casks"
    else:
        raise ValueError(f"kind must be formula or cask, not {kind!r}")
    if on_failure is None:
        on_failure = OnFailure.SPLIT if len(names) > 1 else OnFailure.STOP
    return _batch(instance, host_arch, action_id, args, names, description="reinstall " + what, on_failure=on_failure)


def upgrade_formulae(instance: Instance, host_arch: str, action_id: str, names: Sequence[str],
                     on_failure: OnFailure = OnFailure.SPLIT) -> Action:
    """Upgrade formulae: `brew upgrade --formula <names...>`

    Never without names: a bare `brew upgrade --formula` upgrades every outdated formula.

    @param instance    the Homebrew instance
    @param host_arch   the host's architecture, which decides the `arch` prefix
    @param action_id   the action's `<phase>.<subject>.<step>` id
    @param names       the formulae to upgrade
    @param on_failure  what a failure of the command does
    @returns           the action
    """
    return _batch(instance, host_arch, action_id, ["upgrade", "--formula"], names, description="upgrade formulae",
                  on_failure=on_failure)


def upgrade_casks(instance: Instance, host_arch: str, action_id: str, tokens: Sequence[str],
                  on_failure: OnFailure = OnFailure.SPLIT) -> Action:
    """Upgrade casks that need no password: `brew upgrade --cask <tokens...>`

    Never without tokens: a bare `brew upgrade --cask` upgrades every outdated cask. Homebrew quits an app
    that is open for its upgrade and opens it again.

    @param instance    the Homebrew instance
    @param host_arch   the host's architecture, which decides the `arch` prefix
    @param action_id   the action's `<phase>.<subject>.<step>` id
    @param tokens      the cask tokens to upgrade
    @param on_failure  what a failure of the command does
    @returns           the action
    """
    return _batch(instance, host_arch, action_id, ["upgrade", "--cask"], tokens, description="upgrade casks",
                  on_failure=on_failure)


def unpin(instance: Instance, host_arch: str, action_id: str, names: Sequence[str], *, casks: bool = False) -> Action:
    """Remove the pins of formulae or casks: `brew unpin [--cask] <names...>`

    Formulae go without `--formula`, which a Homebrew that pins formulae alone does not know. A failure is left
    to the upgrade that follows, which Homebrew refuses for a package that is still pinned.

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @param names      the pinned formulae, or the pinned cask tokens
    @param casks      whether the names are casks
    @returns          the action
    """
    return _batch(instance, host_arch, action_id, ["unpin", "--cask"] if casks else ["unpin"], names,
                  description="remove the pins of casks" if casks else "remove the pins of formulae",
                  on_failure=OnFailure.PROBE)


def uninstall_formulae(instance: Instance, host_arch: str, action_id: str, names: Sequence[str], *,
                       split_order: Sequence[str] | None = None,
                       on_failure: OnFailure = OnFailure.SPLIT) -> Action:
    """Uninstall formulae: one `brew uninstall --formula --force <names...>` per instance

    @param instance     the Homebrew instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param names        the formulae to uninstall
    @param split_order  the dependents-first order the names are retried in; None keeps their order
    @param on_failure   what a failure of the command does
    @returns            the action
    """
    return _batch(instance, host_arch, action_id, ["uninstall", "--formula", "--force"], names,
                  description="uninstall formulae", on_failure=on_failure, split_order=split_order)


def uninstall_casks(instance: Instance, host_arch: str, action_id: str, tokens: Sequence[str], *,
                    split_order: Sequence[str] | None = None,
                    on_failure: OnFailure = OnFailure.SPLIT) -> Action:
    """Uninstall casks: one `brew uninstall --cask --force <tokens...>` per instance

    @param instance     the Homebrew instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param tokens       the cask tokens to uninstall
    @param split_order  the order the tokens are retried in; None keeps their order
    @param on_failure   what a failure of the command does
    @returns            the action
    """
    return _batch(instance, host_arch, action_id, ["uninstall", "--cask", "--force"], tokens,
                  description="uninstall casks", on_failure=on_failure, split_order=split_order)


def tab_installed_on_request(instance: Instance, host_arch: str, action_id: str, names: Sequence[str]) -> Action:
    """Mark formulae as installed on request: `brew tab --installed-on-request <names...>`

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @param names      the formulae to mark
    @returns          the action
    """
    argv = _head(instance, host_arch, ["tab", "--installed-on-request"]) + _names(names)
    return _action(instance, action_id, argv, "mark as installed on request")


def bundle_install(instance: Instance, host_arch: str, action_id: str, path: str,
                   on_failure: OnFailure = OnFailure.PROBE) -> Action:
    """Reinstall from a filtered `Brewfile` with `brew bundle install --no-upgrade`

    A probe by default, and without a timeout like every `rollback` command.

    @param instance    the Homebrew instance
    @param host_arch   the host's architecture, which decides the `arch` prefix
    @param action_id   the action's `<phase>.<subject>.<step>` id
    @param path        the filtered `Brewfile`
    @param on_failure  what a failure of the command does
    @returns           the action
    """
    argv = _head(instance, host_arch, ["bundle", "install", "--no-upgrade", "--file=" + path])
    return _action(instance, action_id, argv, f"reinstall from {path}", on_failure=on_failure)


def services_start(instance: Instance, host_arch: str, action_id: str, formula: str,
                   on_failure: OnFailure = OnFailure.STOP) -> Action:
    """Start a formula's service as the user with `brew services start <f>`

    `brew services` writes the plist from the formula's service definition.

    @param instance    the Homebrew instance
    @param host_arch   the host's architecture, which decides the `arch` prefix
    @param action_id   the action's `<phase>.<subject>.<step>` id
    @param formula     the formula whose service starts
    @param on_failure  what a failure of the command does
    @returns           the action
    """
    argv = _head(instance, host_arch, ["services", "start"]) + _names([formula])
    return _action(instance, action_id, argv, f"start the service of {formula}", on_failure=on_failure)


def tap(instance: Instance, host_arch: str, action_id: str, name: str,
        on_failure: OnFailure = OnFailure.STOP) -> Action:
    """Add a tap: `brew tap <user/repo>`

    @param instance    the Homebrew instance
    @param host_arch   the host's architecture, which decides the `arch` prefix
    @param action_id   the action's `<phase>.<subject>.<step>` id
    @param name        the tap, `<user>/<repo>`
    @param on_failure  what a failure of the command does
    @returns           the action
    """
    argv = _head(instance, host_arch, ["tap"]) + _names([name])
    return _action(instance, action_id, argv, f"tap {name}", on_failure=on_failure)


def update(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Update Homebrew and its catalogue with `brew update`, which only `plan --refresh` runs

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @returns          the action
    """
    return _action(instance, action_id, _head(instance, host_arch, ["update"]), "update Homebrew and its catalogue")


def migrate(instance: Instance, host_arch: str, action_id: str, name: str) -> Action:
    """Migrate the keg of a renamed formula from its old name to its current one: `brew migrate <f>`

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @param name       the formula, by the old name its keg carries
    @returns          the action
    """
    argv = _head(instance, host_arch, ["migrate"]) + _names([name])
    return _action(instance, action_id, argv, f"migrate {name} to its new name")


def link(instance: Instance, host_arch: str, action_id: str, name: str) -> Action:
    """Link a formula that is neither linked nor keg-only: `brew link <f>`

    @param instance   the Homebrew instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @param name       the formula to link
    @returns          the action
    """
    argv = _head(instance, host_arch, ["link"]) + _names([name])
    return _action(instance, action_id, argv, f"link {name}")


def _user_argv(instance: Instance, args: Sequence[str], host_arch: str | None) -> list[str]:
    """Return a `brew` command for the user to run

    The `brew` of an Intel Homebrew on an Apple Silicon Mac goes behind `arch -x86_64`: started without it,
    Homebrew refuses to install into `/usr/local`.

    @param instance   the Homebrew instance whose binary the command names
    @param args       the arguments after the binary
    @param host_arch  the host's architecture; None leaves `arch` out
    @returns          the argv
    """
    argv = [instance.binary or f"{instance.prefix}/bin/brew"] + list(args)
    if host_arch == "arm64" and instance.arch == "x86_64":
        argv = arch_argv(instance.arch, host_arch, argv)
    return argv


def typed_line(instance: Instance, args: Sequence[str], host_arch: str | None = None) -> str:
    """Return a `brew` command for the user to run, as they would type it

    @param instance   the Homebrew instance whose binary the command names
    @param args       the arguments after the binary
    @param host_arch  the host's architecture; None leaves `arch` out
    @returns          the shell-quoted command: `brew` by its bare name only where typing that runs this binary
    """
    return typed(_user_argv(instance, args, host_arch), intel=True)


def manual(instance: Instance, action_id: str, args: Sequence[str], description: str,
           host_arch: str | None = None) -> Action:
    """Build a `brew` line that is printed for the user and never run, such as `brew link --overwrite --dry-run <f>`

    @param instance     the Homebrew instance whose binary the line names
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param args         the arguments after the binary
    @param description  the text shown with the line
    @param host_arch    the host's architecture; None leaves `arch` out
    @returns            the action
    """
    return Action(action_id=action_id, kind="command", argv=_user_argv(instance, args, host_arch), sudo=False,
                  description=description, env_profile="brew", manual=True, instance_prefix=instance.prefix)

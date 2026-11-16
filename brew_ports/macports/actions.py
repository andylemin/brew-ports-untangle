"""Builders for every `port` command the tool runs

Mutations run under `sudo` with the `ports` profile; every install and upgrade carries `--no-rev-upgrade`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from .. import runner as runner_mod
from ..model import Action, Instance, OnFailure

NAME_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.+-]*$")
VARIANT_RE = re.compile(r"^[+-][A-Za-z0-9_.]+$")


def _port(instance: Instance) -> str:
    """Return the instance's `port` binary, refusing an instance that has none

    @param instance  the MacPorts instance
    @returns         the path of `<prefix>/bin/port`
    """
    if not instance.binary:
        raise ValueError(f"the MacPorts instance at {instance.prefix} has no port binary")
    return instance.binary


def _name(name: str) -> str:
    """Return a port name, select group or option, refusing a word `port` would read as an option or variant

    @param name  a port name, select group or select option
    @returns     the word, unchanged
    """
    if not NAME_RE.match(name or ""):
        raise ValueError(f"not a port name: {name!r}")
    return name


def _names(names: Sequence[str]) -> list[str]:
    """Return port names without empty entries, refusing an empty list or a word `port` would misread

    @param names  port names
    @returns      the names that are not empty, in their order
    """
    return [_name(n) for n in runner_mod.require_names(names)]


def _variants(tokens: Sequence[str]) -> list[str]:
    """Return variant tokens such as `+ssl` or `-x11`, refusing any other word

    @param tokens  the variant tokens
    @returns       the tokens as a list, in their order
    """
    out = list(tokens)
    for token in out:
        if not VARIANT_RE.match(token):
            raise ValueError(f"not a variant token: {token!r}")
    return out


def _spec(spec: Sequence[str]) -> list[str]:
    """Return `[name, "@<version>_<revision><variants>"]`, the two tokens of one installed version

    @param spec  the `spec_args` pair of a registry row
    @returns     the pair as a list, its name checked
    """
    if len(spec) != 2 or not spec[1].startswith("@") or len(spec[1]) < 2 or any(c.isspace() for c in spec[1]):
        raise ValueError(f"not a spec_args pair: {list(spec)!r}")
    return [_name(spec[0]), spec[1]]


def _trace(homebrew_present: bool) -> list[str]:
    """Return `-t` while a Homebrew prefix exists: trace mode hides it from a build from source

    @param homebrew_present  whether a Homebrew prefix exists on the host
    @returns                 `["-t"]`, or an empty list
    """
    return ["-t"] if homebrew_present else []


def _argv(instance: Instance, host_arch: str, args: Sequence[str]) -> list[str]:
    """Build `port -N <args>` under `arch_argv`: a shell under Rosetta must not make base report a mismatch

    @param instance   the MacPorts instance whose binary the command runs
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param args       the arguments after `port -N`
    @returns          the argv, `arch -<arch>` first on an arm64 host when the instance's architecture is known
    """
    return runner_mod.arch_argv(instance.arch, host_arch, [_port(instance), "-N"] + list(args))


def _command(instance: Instance, host_arch: str, action_id: str, args: Sequence[str], description: str, *,
             sudo: bool = True, on_failure: OnFailure = OnFailure.STOP, **extra) -> Action:
    """Build `port -N <args>` under the `ports` profile

    @param instance     the MacPorts instance whose binary the command runs
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param args         the arguments after `port -N`
    @param description  the text shown for the action
    @param sudo         run the command as root
    @param on_failure   what a failure of the command does
    @param extra        further `Action` fields, such as `retry_argv` or `read_only`
    @returns            the action
    """
    return Action(action_id=action_id, kind="command", argv=_argv(instance, host_arch, args), sudo=sudo,
                  description=description, env_profile="ports", on_failure=on_failure,
                  instance_prefix=instance.prefix, **extra)


def _probe(instance: Instance, host_arch: str, action_id: str, args: Sequence[str], description: str) -> Action:
    """Build a read-only `port -N <args>` probe, run as the user, whose exit status is data

    @param instance     the MacPorts instance whose binary the probe runs
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param args         the arguments after `port -N`
    @param description  the text shown for the probe
    @returns            the action
    """
    return _command(instance, host_arch, action_id, args, description, sudo=False,
                    on_failure=OnFailure.PROBE, read_only=True)


# Read-only probes -----------------------------------------------------------------

def version(instance: Instance, host_arch: str, action_id: str, sudo: bool = False) -> Action:
    """Build `port -N version`: as the user, the usability probe; under `sudo`, a registry repair

    Run as root, base updates the registry schema or creates a missing `registry.db`.

    @param instance     the MacPorts instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param sudo         build the root run that repairs the registry
    @returns            the action
    @throws ValueError  the instance has no `port` binary
    """
    if sudo:
        return _command(instance, host_arch, action_id, ["version"],
                        f"run base once as root to update or create the registry of {instance.prefix}")
    return _probe(instance, host_arch, action_id, ["version"], f"MacPorts base version at {instance.prefix}")


def select_summary(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Build `port -N select --summary`; exit 1 means no select group exists

    @param instance   the MacPorts instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @returns          the action
    """
    return _probe(instance, host_arch, action_id, ["select", "--summary"], f"port select groups of {instance.prefix}")


def diagnose(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Build `port -N diagnose --quiet`, whose warnings become `ports-diagnose-warning` findings

    @param instance   the MacPorts instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @returns          the action
    """
    return _probe(instance, host_arch, action_id, ["diagnose", "--quiet"], f"port diagnose of {instance.prefix}")


# Installs and upgrades ------------------------------------------------------------

def install(instance: Instance, host_arch: str, action_id: str, name: str, variants: Sequence[str] = (), *,
            homebrew_present: bool, binary_first: bool = True, unrequested: bool = False,
            on_failure: OnFailure | None = None) -> Action:
    """Build the install of one port from a binary archive (`-b`), retried from source; else from source

    @param instance          the MacPorts instance
    @param host_arch         the host's architecture, which decides the `arch` prefix
    @param action_id         the action's `<phase>.<subject>.<step>` id
    @param name              the port to install
    @param variants          the variant tokens, such as `+ssl` or `-x11`
    @param homebrew_present  whether a Homebrew prefix exists, which adds `-t` to the build from source
    @param binary_first      try the binary archive first, with the build from source as its retry
    @param unrequested       pass `--unrequested`, as rollback does for a row the user did not request
    @param on_failure        without `binary_first`, what a failure does; None stops the phase
    @returns                 the action
    @throws ValueError       a name or variant `port` would misread, or the instance has no `port` binary
    """
    name = _names([name])[0]
    tail = (["--unrequested"] if unrequested else []) + ["--no-rev-upgrade", name] + _variants(variants)
    source = _trace(homebrew_present) + ["install"] + tail
    if binary_first:
        return _command(instance, host_arch, action_id, ["-b", "install"] + tail,
                        f"install {name} from a binary archive into {instance.prefix}, else build it",
                        on_failure=OnFailure.RETRY_WITH, retry_argv=_argv(instance, host_arch, source))
    return _command(instance, host_arch, action_id, source, f"install {name} into {instance.prefix}",
                    on_failure=on_failure or OnFailure.STOP)


def upgrade(instance: Instance, host_arch: str, action_id: str, name: str, *, homebrew_present: bool,
            no_deps: bool = False) -> Action:
    """Build `sudo port -N [-n] [-t] upgrade --no-rev-upgrade <name>`, which keeps `requested_variants`

    For an outdated mapped target (phase 3), an outdated active row without an image (with `-n`) or
    a replaced port.

    @param instance          the MacPorts instance
    @param host_arch         the host's architecture, which decides the `arch` prefix
    @param action_id         the action's `<phase>.<subject>.<step>` id
    @param name              the port to upgrade
    @param homebrew_present  whether a Homebrew prefix exists, which adds `-t`
    @param no_deps           pass `-n`, which leaves the port's dependencies as they are
    @returns                 the action
    @throws ValueError       a name `port` would misread, or the instance has no `port` binary
    """
    name = _names([name])[0]
    args = (["-n"] if no_deps else []) + _trace(homebrew_present) + ["upgrade", "--no-rev-upgrade", name]
    return _command(instance, host_arch, action_id, args, f"upgrade {name} in {instance.prefix}")


def upgrade_forced(instance: Instance, host_arch: str, action_id: str, name: str,
                   requested_variants: Sequence[str] = (), *, homebrew_present: bool) -> Action:
    """Build a port's rebuild (missing image, broken or cross-prefix linkage): a forced upgrade, retried as install

    The forced upgrade uninstalls the installed version only after its build, so the retry covers
    a failure after that uninstall.

    @param instance            the MacPorts instance
    @param host_arch           the host's architecture, which decides the `arch` prefix
    @param action_id           the action's `<phase>.<subject>.<step>` id
    @param name                the port to rebuild
    @param requested_variants  the variant tokens the install retry passes, as the registry holds them
    @param homebrew_present    whether a Homebrew prefix exists, which adds `-t`
    @returns                   the action
    @throws ValueError         a name or variant `port` would misread, or the instance has no `port` binary
    """
    name = _names([name])[0]
    trace = _trace(homebrew_present)
    primary = ["-n"] + trace + ["upgrade", "--force", "--no-replace", "--no-rev-upgrade", name]
    retry = trace + ["install", "--no-rev-upgrade", name] + _variants(requested_variants)
    return _command(instance, host_arch, action_id, primary, f"rebuild {name} in {instance.prefix}",
                    on_failure=OnFailure.RETRY_WITH, retry_argv=_argv(instance, host_arch, retry))


# Removals and registry flags ------------------------------------------------------

def uninstall(instance: Instance, host_arch: str, action_id: str, specs: Sequence[Sequence[str]], *,
              split_order: Sequence[str] | None = None, on_failure: OnFailure = OnFailure.SPLIT) -> Action:
    """Build `sudo port -N uninstall <spec_args...>`: every version named by its two tokens, never a pseudo-port

    `SPLIT` retries one port at a time in `split_order` (dependents first); a port's group in the
    argv is its name and its `@version` tokens.

    @param instance     the MacPorts instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param specs        the `spec_args` pair of each version, `[name, "@<version>_<revision><variants>"]`
    @param split_order  the port names in retry order, each once; None keeps the order of the specs
    @param on_failure   what a failure of the command does
    @returns            the action
    @throws ValueError  no spec, a malformed one, a `split_order` that is not the batch's ports, or no `port` binary
    """
    tokens: list[str] = []
    names: list[str] = []
    for spec in specs:
        pair = _spec(spec)
        tokens += pair
        if pair[0] not in names:
            names.append(pair[0])
    runner_mod.require_names(names)
    order = list(split_order) if split_order is not None else list(names)
    if len(order) != len(set(order)) or set(order) != set(names):
        raise ValueError(f"split_order must name every port of the batch once: {order!r} against {names!r}")
    head = _argv(instance, host_arch, ["uninstall"])
    return Action(action_id=action_id, kind="command", argv=head + tokens, sudo=True,
                  description=f"uninstall {len(specs)} version(s) of {', '.join(names)} from {instance.prefix}",
                  env_profile="ports", on_failure=on_failure, split_order=order, split_head=len(head),
                  instance_prefix=instance.prefix)


def setrequested(instance: Instance, host_arch: str, action_id: str, names: Sequence[str]) -> Action:
    """Build `sudo port -N setrequested <name...>`: a mapped target held only as a dependency becomes a root

    @param instance   the MacPorts instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @param names      the ports to mark as requested
    @returns          the action
    """
    names = _names(names)
    return _command(instance, host_arch, action_id, ["setrequested"] + names,
                    f"mark {', '.join(names)} as requested in {instance.prefix}")


def deactivate(instance: Instance, host_arch: str, action_id: str, spec: Sequence[str], force: bool = True) -> Action:
    """Build `sudo port -N -f deactivate <spec_args>`; forced, it skips registered files that are missing

    @param instance     the MacPorts instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param spec         the `spec_args` pair of the version to deactivate
    @param force        pass `-f`
    @returns            the action
    @throws ValueError  a malformed spec, or the instance has no `port` binary
    """
    pair = _spec(spec)
    args = (["-f"] if force else []) + ["deactivate"] + pair
    return _command(instance, host_arch, action_id, args, f"deactivate {pair[0]} {pair[1]}")


def activate(instance: Instance, host_arch: str, action_id: str, spec: Sequence[str], force: bool = True) -> Action:
    """Build `sudo port -N -f activate <spec_args>`, which after `deactivate` restores missing files

    Without `force`, it matches the `port activate` line rollback prints to bring back the version an in-place
    upgrade replaced.

    @param instance     the MacPorts instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param spec         the `spec_args` pair of the version to activate
    @param force        pass `-f`
    @returns            the action
    @throws ValueError  a malformed spec, or the instance has no `port` binary
    """
    pair = _spec(spec)
    args = (["-f"] if force else []) + ["activate"] + pair
    return _command(instance, host_arch, action_id, args, f"activate {pair[0]} {pair[1]}")


# Startup items and select groups --------------------------------------------------

def load(instance: Instance, host_arch: str, action_id: str, name: str) -> Action:
    """Build `sudo port -N load <name>`, which starts a startup item in phase 7, a service restart, a repair or rollback

    @param instance     the MacPorts instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param name         the port whose startup item starts
    @returns            the action
    @throws ValueError  a name `port` would misread, or the instance has no `port` binary
    """
    name = _names([name])[0]
    return _command(instance, host_arch, action_id, ["load", name], f"load the startup item of {name}")


def unload(instance: Instance, host_arch: str, action_id: str, name: str) -> Action:
    """Build `sudo port -N unload <name>`, which stops a startup item that phase 7 loaded (rollback)

    @param instance     the MacPorts instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param name         the port whose startup item stops
    @returns            the action
    @throws ValueError  a name `port` would misread, or the instance has no `port` binary
    """
    name = _names([name])[0]
    return _command(instance, host_arch, action_id, ["unload", name], f"unload the startup item of {name}")


def select_set(instance: Instance, host_arch: str, action_id: str, group: str, option: str) -> Action:
    """Build `sudo port -N select --set <group> <option>` (phase 7, rollback; `none` clears a selection)

    @param instance     the MacPorts instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param group        the select group, such as `python3`
    @param option       the option to select, or `none`
    @returns            the action
    @throws ValueError  a group or option `port` would misread, or the instance has no `port` binary
    """
    group, option = _name(group), _name(option)
    return _command(instance, host_arch, action_id, ["select", "--set", group, option],
                    f"select {option} for {group} in {instance.prefix}")


# Snapshots and base maintenance ---------------------------------------------------

def snapshot_create(instance: Instance, host_arch: str, action_id: str, note: str) -> Action:
    """Build `sudo port -N snapshot --create --note <note>`, the snapshot of phase 1

    @param instance   the MacPorts instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @param note       the snapshot's one-line note, `brew-ports <run-id>`
    @returns          the action
    """
    if not note or "\n" in note:
        raise ValueError(f"a snapshot note is one line: {note!r}")
    return _command(instance, host_arch, action_id, ["snapshot", "--create", "--note", note],
                    f"snapshot the ports of {instance.prefix}")


def snapshot_export(instance: Instance, host_arch: str, action_id: str, snapshot_id: int) -> Action:
    """Build `sudo port -N snapshot --export <id>`, an escalated probe without a timeout

    It prints the JSON and then exits 1 on every release that has it, so its exit status is not its result.

    @param instance     the MacPorts instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @param snapshot_id  the id `snapshot --create` gave the snapshot
    @returns            the action
    """
    return _command(instance, host_arch, action_id, ["snapshot", "--export", str(int(snapshot_id))],
                    f"export snapshot {int(snapshot_id)} of {instance.prefix}",
                    on_failure=OnFailure.PROBE, read_only=True)


def migrate_all(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Build `sudo port -N migrate --all` (base 2.10.0 and newer), accepted on a mismatched base

    @param instance     the MacPorts instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @returns            the action
    @throws ValueError  the instance has no `port` binary
    """
    return _command(instance, host_arch, action_id, ["migrate", "--all"],
                    f"rebuild base and the ports of {instance.prefix} for this macOS")


def selfupdate(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Build `sudo port -N selfupdate`, accepted on a mismatched base

    @param instance   the MacPorts instance
    @param host_arch  the host's architecture, which decides the `arch` prefix
    @param action_id  the action's `<phase>.<subject>.<step>` id
    @returns          the action
    """
    return _command(instance, host_arch, action_id, ["selfupdate"], f"update MacPorts base at {instance.prefix}")


def sync(instance: Instance, host_arch: str, action_id: str) -> Action:
    """Build `sudo port -N sync`, run after every base repair, `bootstrap-ports` and `plan --refresh`

    @param instance     the MacPorts instance
    @param host_arch    the host's architecture, which decides the `arch` prefix
    @param action_id    the action's `<phase>.<subject>.<step>` id
    @returns            the action
    @throws ValueError  the instance has no `port` binary
    """
    return _command(instance, host_arch, action_id, ["sync"], f"sync the ports tree of {instance.prefix}")

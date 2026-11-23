"""Stopping, restarting and deleting the launchd services of a package

Phase 5, phase 6, `doctor --fix` and `rollback` share it, so a service stops the same way in each.
"""

from __future__ import annotations

import dataclasses
import os
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from .env import services as env_services
from .macports import actions as mp_actions
from .model import Action, Instance, OnFailure, Service
from .runner import RM, EscalationFailed, Interrupted

LAUNCHCTL = env_services.LAUNCHCTL
EINPROGRESS = 36           # `launchctl bootout` while the job is still stopping
WAIT_EXTRA_S = 10          # a stop waits at most the service's exit_timeout_s plus this
COMMAND_TIMEOUT_S = 120    # user-domain commands only: the runner never times out a sudo command


@dataclass
class StopResult:
    """What `stop` did, service by service"""

    booted: list[Service] = field(default_factory=list)       # booted out here, with the domain they were found in
    not_loaded: list[Service] = field(default_factory=list)   # no job to stop
    still_running: list[tuple[Service, str]] = field(default_factory=list)  # the job or its process outlived the wait
    refused: list[Service] = field(default_factory=list)      # a user's own job (owned=False) is never stopped
    error: BaseException | None = None                     # an interrupt or a sudo failure that ended the stops

    @property
    def ok(self) -> bool:
        """Return whether every service is stopped: phases 5 and 6 end the run with exit 4 otherwise

        @returns  True when no job outlived its wait and no error ended the stops
        """
        return not self.still_running and self.error is None


def _prefix(runner, id_prefix: str | None) -> str:
    """Return the prefix of the action ids: the one given, else the runner's phase

    @param runner     the runner, whose phase counts as 0 when unset
    @param id_prefix  the prefix to use; None for the runner's phase
    @returns          the prefix
    """
    if id_prefix is not None:
        return id_prefix
    return str(runner.phase if runner.phase is not None else 0)


def _target(service: Service) -> str:
    """Return the `<domain>/<label>` service target that `launchctl` takes

    @param service  a service loaded in a domain
    @returns        the target
    """
    return f"{service.domain}/{service.label}"


def pid_alive(pid: int | None) -> bool:
    """Return whether a process runs; a `PermissionError` from `os.kill(pid, 0)` means another user's process

    @param pid  the process id, or None
    @returns    True when the process exists; False for None or a pid below 1
    """
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def bootout_action(service: Service, action_id: str) -> Action:
    """Return `launchctl bootout <domain>/<label>` as a probe, under `sudo` for the system domain

    @param service    a service loaded in a domain
    @param action_id  the action's id
    @returns          the action
    """
    return Action(action_id=action_id, kind="command", argv=[LAUNCHCTL, "bootout", _target(service)],
                  sudo=service.domain == "system", description=f"stop the launchd job {_target(service)}",
                  on_failure=OnFailure.PROBE, timeout_s=COMMAND_TIMEOUT_S)


def _bootout(runner, service: Service, action: Action, booted: list[Service], *, clock: Callable[[], float],
             sleep: Callable[[float], None], alive: Callable[[int | None], bool]) -> str | None:
    """Boot the job out and wait for it and its process to exit

    `bootout` returns before the job exits, so it repeats every second while it returns 36 or the job is listed.

    @param runner   the runner of the `launchctl` commands
    @param service  the service, probed afresh and loaded in a domain
    @param action   its `launchctl bootout` probe
    @param booted   receives the service after its first `bootout`
    @param clock    returns the monotonic time in seconds
    @param sleep    waits for a number of seconds
    @param alive    returns whether a pid still runs
    @returns        why the job still runs, or None once it and its process have exited
    """
    if not service.domain:
        raise ValueError(f"{service.label} is loaded in no launchd domain, so it cannot be booted out")
    limit = service.exit_timeout_s + WAIT_EXTRA_S
    deadline = clock() + limit
    first = True
    while True:
        code = runner.run(action, defer_result=True).exit
        if first:
            booted.append(service)
            first = False
        present = code == EINPROGRESS or \
            env_services.print_job(runner, service.domain, service.label) is not None
        if not present or clock() >= deadline:
            break
        sleep(1.0)
    if present:
        return f"the service {service.label} did not stop within {limit} s"
    if alive(service.pid):
        return f"process {service.pid} of the service {service.label} is still running"
    return None


def stop(runner, services: Sequence[Service], uid: int, *, id_prefix: str | None = None,
         clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
         alive: Callable[[int | None], bool] = pid_alive) -> StopResult:
    """Stop each owned service and wait for it to exit

    Each is probed again first, so `domain`, `loaded` and `pid` are current. An interrupt or a sudo failure
    ends the loop in `error`, so the caller can still start every service in `booted` again.

    @param runner     the runner of the `launchctl` commands
    @param services   the services to stop; a user's own job is refused
    @param uid        the user's uid, which names the `gui/<uid>` and `user/<uid>` domains
    @param id_prefix  the prefix of the action ids; None for the runner's phase
    @param clock      returns the monotonic time in seconds
    @param sleep      waits for a number of seconds
    @param alive      returns whether a pid still runs
    @returns          what happened to each service
    """
    out = StopResult()
    prefix = _prefix(runner, id_prefix)
    for service in services:
        if not service.owned:
            out.refused.append(service)
            continue
        try:
            current = env_services.refresh(runner, service, uid)
            if not current.loaded or not current.domain:
                out.not_loaded.append(current)
                continue
            action = bootout_action(current, f"{prefix}.stop.{current.label}")
            reason = _bootout(runner, current, action, out.booted, clock=clock, sleep=sleep, alive=alive)
        except (Interrupted, EscalationFailed) as exc:
            out.error = exc
            break
        runner.record_result(action, reason is None)
        if reason is not None:
            out.still_running.append((current, reason))
    return out


def _restart_action(runner, service: Service, instance: Instance | None, action_id: str) -> Action | None:
    """Return `sudo port -N load <name>` for a startup item of a drivable MacPorts, else `launchctl bootstrap`

    Both are probes, so one failure does not stop the other restarts.

    @param runner     the runner, for its host architecture
    @param service    the booted-out service
    @param instance   the instance whose program the service runs, or None
    @param action_id  the action's id
    @returns          the action, or None when neither applies: no `port load` and no recorded domain
    """
    if service.package_kind == "port" and service.package and instance is not None and instance.drivable \
            and instance.binary:
        try:
            return dataclasses.replace(mp_actions.load(instance, runner.host_arch, action_id, service.package),
                                       on_failure=OnFailure.PROBE)
        except ValueError:
            pass
    if not service.domain:
        return None
    return Action(action_id=action_id, kind="command", argv=[LAUNCHCTL, "bootstrap", service.domain, service.plist],
                  sudo=service.domain == "system",
                  description=f"start {service.label} again from {service.plist}",
                  on_failure=OnFailure.PROBE, timeout_s=COMMAND_TIMEOUT_S)


def _restart_one(runner, service: Service, instance: Instance | None, action_id: str) -> bool:
    """Start one service again, unless launchd already lists it in its recorded domain

    @param runner     the runner of the `launchctl` and `port` commands
    @param service    the booted-out service
    @param instance   the instance whose program the service runs, or None
    @param action_id  the action's id
    @returns          whether the service is loaded afterwards
    """
    if service.domain and env_services.print_job(runner, service.domain, service.label) is not None:
        return True
    action = _restart_action(runner, service, instance, action_id)
    if action is None:
        return False
    try:
        return runner.run(action).exit == 0
    except EscalationFailed:
        return False


def restart(runner, services: Sequence[Service], instances: Sequence[Instance] = (), *,
            id_prefix: str | None = None) -> list[tuple[Service, bool]]:
    """Start the booted-out services again in their recorded domains

    This runs in the runner's cleanup mode, so the services start again after an interrupt too.

    @param runner     the runner of the `launchctl` and `port` commands
    @param services   the services `stop` booted out
    @param instances  the instances, for the `port load` of a MacPorts startup item
    @param id_prefix  the prefix of the action ids; None for the runner's phase
    @returns          each service with whether it is loaded afterwards
    """
    by_prefix: dict[str, Instance] = {inst.prefix: inst for inst in instances}
    prefix = _prefix(runner, id_prefix)
    out: list[tuple[Service, bool]] = []
    with runner.cleanup():
        for service in services:
            ok = _restart_one(runner, service, by_prefix.get(service.instance_prefix),
                              f"{prefix}.restart.{service.label}")
            out.append((service, ok))
    return out


def delete_plists(runner, services: Sequence[Service], *,
                  id_prefix: str | None = None) -> list[tuple[Service, bool]]:
    """Delete the plists of owned services whose package is gone

    `rm -f` runs under `sudo` for the system scope or a directory the user cannot write.

    @param runner     the runner of the `rm` commands
    @param services   the services whose plists go; a user's own job is skipped
    @param id_prefix  the prefix of the action ids; None for the runner's phase
    @returns          each owned service with whether its plist is gone
    """
    prefix = _prefix(runner, id_prefix)
    out: list[tuple[Service, bool]] = []
    for service in services:
        if not service.owned:
            continue
        if os.path.lexists(service.plist):
            directory = os.path.dirname(service.plist) or "."
            action = Action(action_id=f"{prefix}.plist.{service.label}", kind="command",
                            argv=[RM, "-f", service.plist],
                            sudo=service.scope == "system" or not os.access(directory, os.W_OK),
                            description=f"delete the plist {service.plist}", on_failure=OnFailure.PROBE,
                            timeout_s=COMMAND_TIMEOUT_S)
            try:
                runner.run(action)
            except EscalationFailed:
                pass
        out.append((service, not os.path.lexists(service.plist)))
    return out

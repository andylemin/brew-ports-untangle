"""The installation that stays, for `doctor`: which one `--target` names, and how a finding weighs on that move"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from . import doctor_report
from .homebrew import locate as brew_locate
from .macports import locate as mp_locate
from .model import Blocks, Instance, Issue, Manager
from .report import MANAGER_NAMES


class NoTarget(Exception):
    """`--target` names no installation to keep, or `--fix` lacks it: the line that says why"""

    def __init__(self, text: str, usage: bool) -> None:
        """Carry the error to `cmd_doctor`

        @param text   the error
        @param usage  whether an option is missing or fits several installations (exit 2); otherwise the
                      installation it names is missing (exit 3)
        """
        super().__init__(text)
        self.usage = usage


def kept_instance(args: Any, instances: Sequence[Instance], host_arch: str,
                  environ: Mapping[str, str]) -> Instance | None:
    """Return the installation that the user keeps: the one `--target` names, else the only one of a `--fix` run

    `--target` names the installation of that manager at `--target-prefix`. Without a prefix it names the only
    one of that manager, or of several the one that `plan` moves into.

    @param args       the parsed command line
    @param instances  the installations the scan found
    @param host_arch  the Mac's architecture, which decides Homebrew's usual place
    @param environ    the environment, for `HOMEBREW_PREFIX`
    @returns          the installation; None for a report without `--target`, and on a Mac without one
    @throws NoTarget  a `--fix` or `--dry-run` without `--target` on a Mac with several installations, a
                      `--target` that fits several, or one that names none
    """
    fixing = args.fix or args.dry_run
    if not args.target:
        if fixing and len(instances) > 1:
            raise NoTarget(doctor_report.needs_target(doctor_report.known(instances)), True)
        return instances[0] if fixing and instances else None
    manager = Manager(args.target)
    found = [inst for inst in instances if inst.manager is manager]
    if args.target_prefix:
        inst = brew_locate.find_by_path(found, args.target_prefix)
    elif len(found) == 1:
        inst = found[0]
    elif manager is Manager.BREW:
        inst = brew_locate.choose_target(found, host_arch, None, environ)
    else:
        inst = mp_locate.choose_target(found, host_arch, None)
    if inst is None:
        raise NoTarget(doctor_report.no_target(MANAGER_NAMES[manager], args.target_prefix, found),
                       len(found) > 1 and not args.target_prefix)
    return inst


def weigh_for(issues: Sequence[Issue], target: Instance, instances: Sequence[Instance]) -> None:
    """Keep of each finding's `blocks` those that hold for the move into the installation that stays

    A finding about that installation stops the move only where it stops a move into it; one about another
    installation, only where it stops a move out of it or its removal.

    @param issues     the findings; one about an installation is changed in place
    @param target     the installation that stays
    @param instances  the installations the scan found
    """
    leaving = (Blocks.ANY, Blocks.UNINSTALL, Blocks.CASKS, Blocks.REMOVE)
    prefixes = {inst.prefix for inst in instances}
    for issue in issues:
        if issue.instance_prefix in prefixes:
            holds = (Blocks.ANY, Blocks.TARGET) if issue.instance_prefix == target.prefix else leaving
            issue.blocks = tuple(block for block in issue.blocks if block in holds)

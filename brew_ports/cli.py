"""Command-line front end: the parser, the exit codes and the refusals"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Sequence
from typing import Any

from . import (__version__, doctor, envclean, executor, planner, progress, recommend, report, rollback,
               runner as runner_mod, scan as scan_mod, state as state_mod, system, verify)
from .context import Context
from .macports import bootstrap as mp_bootstrap, locate as mp_locate

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_PREFLIGHT = 3
EXIT_ACTION = 4

ALIAS_MESSAGE = "run brew-ports directly; brew replaces the environment"
MANAGERS = {"brew": "brew", "homebrew": "brew", "ports": "ports", "macports": "ports"}
CASK_POLICIES = {"keep": "keep", "uninstall": "drop", "replace": "map"}     # --casks, as the planner knows it


class UsageError(Exception):
    """A refused option combination (exit 2)"""


def _global_options(parser: argparse.ArgumentParser, suppress: bool) -> None:
    """Add the global options, accepted before and after the subcommand

    On the subparsers the defaults are suppressed: a subparser default would otherwise overwrite a value given
    before the subcommand.

    @param parser    the parser that takes the options
    @param suppress  suppress their defaults, for the parent parser the subparsers inherit from
    """
    def default(value):
        return argparse.SUPPRESS if suppress else value

    parser.add_argument("--state-dir", metavar="DIR", default=default(None),
                        help="state directory (default ~/Library/Application Support/brew-ports)")
    parser.add_argument("--verbose", action="store_true", default=default(False), help="print more detail")
    parser.add_argument("--quiet", action="store_true", default=default(False), help="print only results and errors")
    parser.add_argument("--redact", action="store_true", default=default(False),
                        help="redact the home directory and login name in the output")


def _manager(value: str) -> str:
    """Return the manager an option names, by either of its names

    @param value                        `brew` or `homebrew`, `ports` or `macports`, in any case
    @returns                            `brew` or `ports`
    @throws argparse.ArgumentTypeError  for any other word
    """
    try:
        return MANAGERS[value.lower()]
    except KeyError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a manager: give brew (Homebrew) or ports "
                                         "(MacPorts)") from None


def _casks(value: str) -> str:
    """Return the cask policy `--casks` names, as the planner knows it

    @param value                        `keep`, `uninstall` or `replace`
    @returns                            `keep`, `drop` or `map`
    @throws argparse.ArgumentTypeError  for any other word
    """
    try:
        return CASK_POLICIES[value.lower()]
    except KeyError:
        raise argparse.ArgumentTypeError(f"{value!r} is not one of keep, uninstall, replace") from None


def _add_plan(sub: Any, common: argparse.ArgumentParser) -> None:
    """Add `plan` and its options to the subcommands

    @param sub     the subcommands of the main parser
    @param common  the parser of the global options, which every subcommand inherits
    """
    p = sub.add_parser(
        "plan", parents=[common], allow_abbrev=False, help="work out a move of your packages; changes nothing",
        description="Work out what moving your packages into one manager would install, leave and uninstall. "
                    "A full move also uninstalls each old Homebrew or MacPorts that it leaves empty. "
                    "Changes nothing on this Mac; writes plan.json for `brew-ports apply`.",
        epilog="Example: brew-ports plan --target brew --out plan.json")
    p.add_argument("--target", required=True, type=_manager, metavar="brew|ports",
                   help="the manager the packages move into: brew (Homebrew) or ports (MacPorts); "
                        "`brew-ports recommend` says which")
    p.add_argument("--target-prefix", metavar="PATH",
                   help="its folder, when this Mac has several installations of it (default: /opt/homebrew, or "
                        "/usr/local on Intel; /opt/local for MacPorts)")
    p.add_argument("--only", action="append", metavar="NAME[,NAME...]",
                   help="move only these packages, with the dependencies nothing else needs; no manager is "
                        "uninstalled")
    p.add_argument("--leave", dest="keep", action="append", metavar="NAME[,NAME...]",
                   help="leave these packages, and what they need, in the old installation")
    p.add_argument("--uninstall", dest="drop", action="append", metavar="NAME[,NAME...]",
                   help="uninstall these packages without a replacement; for packages that have none")
    p.add_argument("--replace", dest="map", action="append", metavar="OLD=NEW",
                   help="use the package NEW as the replacement of OLD; repeat the option for more")
    p.add_argument("--accept-closest", dest="accept_medium", action="store_true",
                   help="where a package has no exact replacement, take the closest match without asking")
    p.add_argument("--casks", type=_casks, metavar="keep|uninstall|replace",
                   help="with --target ports, what becomes of Homebrew's apps (casks): keep them, and Homebrew with "
                        "them (default); uninstall them; or replace each with its port, ask about one that has only "
                        "a closest match, and uninstall those that have none")
    p.add_argument("--pipx", dest="lang_packages", action="store_const", const="pipx", default="report",
                   help="reinstall Python tools that have no replacement with pipx, which looks them up on "
                        "pypi.org; by default they are only listed")
    p.add_argument("--start-services", action="store_true",
                   help="start the replacement of each service that was running")
    p.add_argument("--upgrade-all", action="store_true",
                   help="upgrade every package that has a newer version in the installation the packages move into, "
                        "not only those the replacements need; asks before it removes a pin, and lists what it "
                        "leaves as it is")
    p.add_argument("--keep-managers", action="store_true",
                   help="do not uninstall the old Homebrew or MacPorts that the move leaves empty")
    p.add_argument("--delete", action="append", metavar="PATH[,PATH...]",
                   help="after the move, delete the old installation at PATH whole, although its command cannot run")
    p.add_argument("--repology", action="store_true",
                   help="look up packages without a known replacement on repology.org (uses the network)")
    p.add_argument("--refresh", action="store_true",
                   help="first update the package list of the manager the packages move into (brew update, or sudo "
                        "port sync); asks before it runs, unless --yes is given")
    p.add_argument("--rescan", action="store_true",
                   help="scan the Mac again instead of using a scan taken in the last ten minutes")
    p.add_argument("--yes", action="store_true",
                   help="do not ask: each question about a package takes its default, so no closest match is taken "
                        "and no pin is removed; the update of --refresh runs")
    p.add_argument("--out", metavar="FILE", help="also save the plan as FILE, for `brew-ports apply FILE`")


def build_parser() -> argparse.ArgumentParser:
    """Build the parser of every subcommand

    @returns  the parser
    """
    common = argparse.ArgumentParser(add_help=False)
    _global_options(common, suppress=True)

    parser = argparse.ArgumentParser(
        prog="brew-ports", allow_abbrev=False,
        description="Inventory Homebrew and MacPorts on this Mac, check their health, and migrate to one of them.")
    _global_options(parser, suppress=False)
    parser.add_argument("--version", action="version", version="brew-ports " + __version__)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    p = sub.add_parser("scan", parents=[common], allow_abbrev=False,
                       help="inventory both managers and the environment")
    p.add_argument("--json", action="store_true", help="print scan.json")
    p.add_argument("--deep", action="store_true", help="scan the binaries of every keg, not only local builds")

    p = sub.add_parser("doctor", parents=[common], allow_abbrev=False, help="health checks, with --fix to repair")
    p.add_argument("--json", action="store_true")
    p.add_argument("--deep", action="store_true")
    p.add_argument("--rescan", action="store_true", help="take a fresh inventory")
    p.add_argument("--fix", action="store_true", help="apply the remedies, confirmed on the terminal")
    p.add_argument("--yes", action="store_true", help="answer the confirmations (never the per-item removals)")
    p.add_argument("--dry-run", action="store_true", help="print the remedies, run nothing")

    p = sub.add_parser("recommend", parents=[common], allow_abbrev=False, help="which manager to keep")
    p.add_argument("--json", action="store_true")
    p.add_argument("--rescan", action="store_true")

    p = sub.add_parser("bootstrap-ports", parents=[common], allow_abbrev=False,
                       help="install MacPorts base from the signed package")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--dry-run", action="store_true")

    _add_plan(sub, common)

    p = sub.add_parser("apply", parents=[common], allow_abbrev=False, help="run a plan")
    p.add_argument("plan", nargs="?", metavar="PLAN")
    p.add_argument("--resume", metavar="RUN-ID")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--stop-after", type=int, metavar="N", choices=range(0, 9))

    p = sub.add_parser("verify", parents=[common], allow_abbrev=False, help="check a migration")
    p.add_argument("plan", nargs="?", metavar="PLAN")

    p = sub.add_parser("env-cleanup", parents=[common], allow_abbrev=False, help="clean the shell environment")
    p.add_argument("--target", type=_manager, metavar="brew|ports")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("rollback", parents=[common], allow_abbrev=False, help="reinstall what a run removed")
    p.add_argument("run_id", metavar="RUN-ID")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    return parser


def cmd_scan(ctx: Context) -> int:
    """Run `scan`: always inventory afresh and write `scan.json`

    @param ctx  the command's context
    @returns    the exit code
    """
    run_dir, runner = runner_mod.start_run(ctx, None)
    with runner.signals():
        bundle = scan_mod.build(runner, ctx.environ, deep=bool(ctx.args.deep))
    try:
        scan_mod.write(bundle, run_dir)
        if ctx.args.json:
            ctx.console.json(bundle.result)
        else:
            for line in scan_mod.render(bundle):
                ctx.console.out(line)
    finally:
        bundle.close()
    return EXIT_OK


def cmd_bootstrap_ports(ctx: Context) -> int:
    """Install MacPorts base from the signed package on a host without MacPorts

    @param ctx  the command's context
    @returns    the exit code
    """
    run_dir, runner = runner_mod.start_run(ctx, 0)
    with runner.signals():
        existing = mp_locate.find_instances(runner, ctx.environ, runner.host_arch)
        if existing:
            ctx.console.warn(f"brew-ports: MacPorts is already installed at {', '.join(i.prefix for i in existing)}; "
                             "`brew-ports doctor --fix` repairs a broken base")
            return EXIT_PREFLIGHT
        version = system.macos_version(runner)
        for line in mp_bootstrap.describe(mp_bootstrap.macos_major(version)):
            ctx.console.out(line)
        if ctx.args.dry_run:
            return EXIT_OK
        if not ctx.confirm("Install MacPorts base?", default=False):
            ctx.console.info("nothing changed")
            return EXIT_OK
        runner.sudo_preflight()
        ctx.state.touch_dirty(run_dir.run_id, "bootstrap-ports")
        runner.phase = 1
        instance = mp_bootstrap.bootstrap(runner, run_dir, ctx.environ, runner.host_arch, macos_version=version)
    ctx.console.out(f"MacPorts {instance.version or ''} installed at {instance.prefix}")
    return EXIT_OK


def cmd_doctor(ctx: Context) -> int:
    """Run `doctor`: the health checks, `doctor.json`, and `--fix`

    @param ctx  the command's context
    @returns    the exit code
    """
    return doctor.cmd_doctor(ctx)


def cmd_recommend(ctx: Context) -> int:
    """Run `recommend`: both directions scored, the table and the sentence

    @param ctx  the command's context
    @returns    the exit code
    """
    return recommend.cmd_recommend(ctx)


def cmd_plan(ctx: Context) -> int:
    """Run `plan`: write `plan.json`, or `plan-refused.json` with the refusals

    @param ctx  the command's context
    @returns    the exit code
    """
    return planner.cmd_plan(ctx)


def cmd_apply(ctx: Context) -> int:
    """Run `apply PLAN` or `apply --resume RUN-ID`: phases 0 to 8 with the journal

    @param ctx  the command's context
    @returns    the exit code
    """
    return executor.cmd_apply(ctx)


def cmd_verify(ctx: Context) -> int:
    """Run `verify [PLAN]`: read the plan and the host afresh, exit 5 on a failure

    @param ctx  the command's context
    @returns    the exit code
    """
    return verify.cmd_verify(ctx)


def cmd_env_cleanup(ctx: Context) -> int:
    """Run `env-cleanup`: the survivor set, the diff of every environment edit, and `--apply`

    @param ctx  the command's context
    @returns    the exit code
    """
    return envclean.cmd_env_cleanup(ctx)


def cmd_rollback(ctx: Context) -> int:
    """Run `rollback RUN-ID [--yes] [--dry-run]`: reinstall what a run removed

    @param ctx  the command's context
    @returns    the exit code
    """
    return rollback.cmd_rollback(ctx)


COMMANDS: dict[str, Callable[[Context], int]] = {
    "scan": cmd_scan,
    "doctor": cmd_doctor,
    "recommend": cmd_recommend,
    "bootstrap-ports": cmd_bootstrap_ports,
    "plan": cmd_plan,
    "apply": cmd_apply,
    "verify": cmd_verify,
    "env-cleanup": cmd_env_cleanup,
    "rollback": cmd_rollback,
}


def check_usage(args: argparse.Namespace) -> None:
    """Refuse the option combinations argparse cannot express (exit 2)

    An option of `plan` that names nothing is refused, so that an empty `--only` never plans a full move.

    @param args         the parsed command line
    @throws UsageError  for `apply` without exactly one of PLAN and `--resume`, a `plan` list option without a
                        name, or `--delete` with `--only`
    """
    if args.command == "apply":
        if bool(args.plan) == bool(args.resume):
            raise UsageError("apply needs exactly one of PLAN or --resume RUN-ID")
    if args.command != "plan":
        return
    for flag, values, noun in (("--only", args.only, "package"), ("--leave", args.keep, "package"),
                               ("--uninstall", args.drop, "package"), ("--delete", args.delete, "folder")):
        if values is not None and not planner.split_names(values):
            raise UsageError(f"{flag} names nothing: give it at least one {noun}")
    if args.delete and args.only:
        raise UsageError(planner.ONLY_DELETES_NOTHING)


def main(argv: Sequence[str] | None = None, environ: dict[str, str] | None = None) -> int:
    """Run one command line and return its exit code

    @param argv         the arguments after the program name; None for those of `sys.argv`
    @param environ      the environment; None for the process's own
    @returns            the subcommand's exit code, or 2, 3 or 4 for a usage, precondition or action error
    @throws SystemExit  argparse's own exit: 0 after `--help` or `--version`, 2 for a line it cannot parse
    """
    env = dict(os.environ if environ is None else environ)
    if "HOMEBREW_COMMAND" in env or "HOMEBREW_BREW_FILE" in env:
        sys.stderr.write(ALIAS_MESSAGE + "\n")
        return EXIT_USAGE
    parser = build_parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    console = report.Console(quiet=args.quiet, verbose=args.verbose, redact=args.redact)
    console.json_mode = bool(getattr(args, "json", False))
    try:
        check_usage(args)
    except UsageError as exc:
        console.error(str(exc))
        return EXIT_USAGE
    if system.running_as_root():
        console.error(system.ROOT_MESSAGE)
        return EXIT_PREFLIGHT
    state = state_mod.StateDir(args.state_dir)
    ctx = Context(args, console, state, environ=env)
    handler = COMMANDS[args.command]
    try:
        with state.lock(), progress.shown(console, args.command, env):
            return handler(ctx)
    except state_mod.LockHeld as exc:
        console.error(str(exc))
        return EXIT_PREFLIGHT
    except UsageError as exc:
        console.error(str(exc))
        return EXIT_USAGE
    except runner_mod.PreflightError as exc:
        console.error(str(exc))
        return EXIT_PREFLIGHT
    except (runner_mod.ActionFailed, runner_mod.EscalationFailed, runner_mod.Interrupted) as exc:
        console.error(str(exc))
        return EXIT_ACTION


if __name__ == "__main__":
    sys.exit(main())

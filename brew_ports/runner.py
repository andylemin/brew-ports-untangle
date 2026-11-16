"""The only place the tool starts processes

Environment profiles, failure policies, the journal, sudo and signals, with `CommandRunner` for real children and
`FakeRunner` for the tests.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypedDict

from . import system
from .model import Action, OnFailure
from .report import Console
from .state import RunDir, now_iso, slug

if TYPE_CHECKING:
    from .context import Context

SUDO = "/usr/bin/sudo"
KILL = "/bin/kill"
ARCH = "/usr/bin/arch"
CURL = "/usr/bin/curl"
INSTALL = "/usr/bin/install"
MKDIR = "/bin/mkdir"
CP = "/bin/cp"
RM = "/bin/rm"
TEST = "/bin/test"
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
PROBE_TIMEOUT_S = 120
KEEPALIVE_S = 60

PROXY_VARIABLES = (
    "http_proxy", "https_proxy", "ftp_proxy", "all_proxy", "no_proxy",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "RSYNC_PROXY",
)
PASS_THROUGH = (
    "HOME", "USER", "LOGNAME", "TMPDIR", "TERM", "LANG", "SSH_AUTH_SOCK", "SUDO_ASKPASS",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "SSH_TTY", "SSH_CONNECTION", "SSH_CLIENT",
) + PROXY_VARIABLES
BREW_SET = {
    "HOMEBREW_NO_AUTO_UPDATE": "1",
    "HOMEBREW_NO_AUTOREMOVE": "1",
    "HOMEBREW_NO_INSTALL_UPGRADE": "1",
    "HOMEBREW_NO_ENV_HINTS": "1",
    "HOMEBREW_NO_INSTALL_CLEANUP": "1",
    "HOMEBREW_NO_EMOJI": "1",
    "HOMEBREW_NO_COLOR": "1",
    "HOMEBREW_NO_ASK": "1",            # newer Homebrew asks before an install; older ones reject its -y switch
    "HOMEBREW_NO_SUDO": "1",
}
BREW_DENY = frozenset((
    "HOMEBREW_DEVELOPER", "HOMEBREW_DEV_CMD_RUN", "HOMEBREW_AUTO_UPDATE_SECS",
    "HOMEBREW_FORCE_API_AUTO_UPDATE", "HOMEBREW_COLOR", "HOMEBREW_VERBOSE", "HOMEBREW_DEBUG",
    "HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK", "HOMEBREW_COMMAND", "HOMEBREW_BREW_FILE",
    "HOMEBREW_PATH", "HOMEBREW_SUDO_CHECKED", "HOMEBREW_SUDO_THROUGH_SUDO_USER",
))
BREW_DENY_PREFIXES = ("HOMEBREW_BUNDLE_", "HOMEBREW_UPGRADE_GREEDY", "HOMEBREW_FORCE_BREW_WRAPPER")
PRESERVE_ENV_REFUSAL = "sudo: sorry, you are not allowed to"


class RunnerError(Exception):
    """The base of the errors the runner raises"""


class ActionFailed(RunnerError):
    """A `STOP` action failed (exit 4 in apply and doctor --fix)"""

    def __init__(self, result: "Result") -> None:
        """Carry the result of the failed action

        @param result  the action's result
        """
        super().__init__(f"{result.action_id} failed with exit {result.exit}")
        self.result = result


class EscalationFailed(RunnerError):
    """`sudo` itself failed (an expired ticket, a refused option): exit 4"""

    def __init__(self, message: str, result: "Result" | None = None) -> None:
        """Carry the failure and the result of the command sudo ran, if it ran one

        @param message  what failed
        @param result   the escalated command's result; None when no command ran
        """
        super().__init__(message)
        self.result = result


class Interrupted(RunnerError):
    """SIGINT, SIGHUP or SIGTERM arrived; the child was waited for (exit 4)"""


class PreflightError(RunnerError):
    """A precondition failed before anything changed (exit 3)"""


@dataclass
class Result:
    """The outcome of a command action: its exit status, its output files and its failure policy's verdict"""

    action_id: str
    exit: int
    stdout_path: str | None
    stderr_path: str | None
    duration_s: float = 0.0
    timed_out: bool = False
    failed: list[str] = field(default_factory=list)   # SPLIT: the names that failed; RETRY_WITH: the action id
    ok: bool = True
    retry: "Result" | None = None

    def stdout(self) -> str:
        """Return the command's standard output

        @returns  the text, invalid UTF-8 replaced; empty when there is no file
        """
        return _read(self.stdout_path)

    def stderr(self) -> str:
        """Return the command's standard error

        @returns  the text, invalid UTF-8 replaced; empty when there is no file
        """
        return _read(self.stderr_path)


def _read(path: str | None) -> str:
    """Return a captured output file as text

    @param path  the file, or None
    @returns     the text, invalid UTF-8 replaced; empty without a path or a file
    """
    if not path:
        return ""
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except FileNotFoundError:
        return ""


# Environment profiles ------------------------------------------------------

def profile_env(profile: str, inherited: Mapping[str, str], prefix: str | None = None) -> dict[str, str]:
    """Return the environment a child gets under the `brew`, `ports` or `neutral` profile

    It is built from the pass-through names, plus for `brew` the user's `HOMEBREW_*` settings outside
    the deny-list, so `DYLD_*`, build variables, `PYTHONPATH` and the like never reach a child.

    @param profile    `brew`, `ports` or `neutral`
    @param inherited  the environment the profile filters
    @param prefix     the instance prefix, whose `bin` and `sbin` lead `PATH`; `brew` and `ports` need it
    @returns          the child's environment
    """
    env = {k: v for k, v in inherited.items() if k in PASS_THROUGH or k.startswith("LC_")}
    if profile == "brew":
        if not prefix:
            raise ValueError("the brew profile needs the instance prefix")
        for key, value in inherited.items():
            if (key.startswith("HOMEBREW_") and key not in BREW_DENY
                    and not key.startswith(BREW_DENY_PREFIXES) and key not in BREW_SET):
                env[key] = value
        env.update(BREW_SET)
        env["PATH"] = f"{prefix}/bin:{prefix}/sbin:{SYSTEM_PATH}"
    elif profile == "ports":
        if not prefix:
            raise ValueError("the ports profile needs the instance prefix")
        env["PATH"] = f"{prefix}/bin:{prefix}/sbin:{SYSTEM_PATH}"
        env["COLUMNS"] = "200"
    elif profile == "neutral":
        env["PATH"] = SYSTEM_PATH
    else:
        raise ValueError(f"unknown environment profile {profile!r}")
    return env


# Argv helpers --------------------------------------------------------------

def arch_argv(instance_arch: str | None, host_arch: str, argv: Sequence[str]) -> list[str]:
    """Prefix a `brew` or `port` argv with `arch` on an arm64 host

    @param instance_arch  the architecture of the instance's interpreter: arm64, x86_64 or None
    @param host_arch      the hardware architecture
    @param argv           the command
    @returns              the command behind `arch -<arch>` on an arm64 host when the instance's architecture
                          is known; the command alone otherwise
    """
    if host_arch == "arm64" and instance_arch in ("arm64", "x86_64"):
        return [ARCH, "-" + instance_arch] + list(argv)
    return list(argv)


def require_names(names: Sequence[str]) -> list[str]:
    """Return names without empty entries, refusing a list with none left

    `brew upgrade` without names acts on every outdated formula and cask, and `port` on the port
    in the current directory.

    @param names  the package names of a manager command
    @returns      the names that are not empty, in their order
    """
    names = [n for n in names if n]
    if not names:
        raise ValueError("refusing to build a manager command without names")
    return names


def curl_argv(url: str, output: str, user_agent: str | None = None) -> list[str]:
    """Return the curl argv that downloads a URL to a file; every HTTPS request of the tool uses it

    `-q` must come first: it stops curl from reading `~/.curlrc`.

    @param url         an `https://` URL; any other scheme is refused
    @param output      the file curl writes
    @param user_agent  the `User-Agent` header; None for curl's own
    @returns           the argv
    """
    if not url.startswith("https://"):
        raise ValueError(f"only https URLs are fetched: {url!r}")
    argv = [CURL, "-q", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https",
            "--tlsv1.2", "--silent", "--show-error", "--output", output]
    if user_agent:
        argv += ["--user-agent", user_agent]
    return argv + [url]


def split_argv(action: Action, name: str) -> list[str]:
    """Return the argv of one name of a `SPLIT` batch: the command plus every group of that name

    A group runs from a name of `split_order` to the next one, as a port's name and its `@version`
    tokens; a name may have several groups.

    @param action  the batch action
    @param name    a name of its `split_order`; a name without a group is refused
    @returns       the argv
    """
    head = action.argv[:action.split_head]
    tail = action.argv[action.split_head:]
    names = set(action.split_order)
    out: list[str] = []
    current: str | None = None
    for token in tail:
        if token in names:
            current = token
        if current == name:
            out.append(token)
    if not out:
        raise ValueError(f"{name} is not in the batch {action.action_id}")
    return list(head) + out


def sudo_argv(argv: Sequence[str], env: Mapping[str, str], preserve_refused: bool) -> list[str]:
    """Return `/usr/bin/sudo -n [--preserve-env=<names>] -- <program> <args...>`

    @param argv              the command, without sudo
    @param env               the child's environment; the proxy variables it holds are preserved by name
    @param preserve_refused  whether sudo refused `--preserve-env` before, which leaves it out
    @returns                 the escalated argv
    """
    names = [v for v in PROXY_VARIABLES if v in env]
    out = [SUDO, "-n"]
    if names and not preserve_refused:
        out.append("--preserve-env=" + ",".join(names))
    out.append("--")
    return out + list(argv)


class _GroupKwargs(TypedDict, total=False):
    """The Popen arguments that place a child: a process group of its own, or a session of its own"""

    process_group: int
    start_new_session: bool


def _group_kwargs() -> _GroupKwargs:
    """Return the Popen arguments of an own process group inside the tool's session, never a new session

    @returns  `process_group=0`
    """
    return {"process_group": 0}


def _spawn(argv: Sequence[str], env: Mapping[str, str], out_fd: int, err_fd: int,
           group: _GroupKwargs) -> subprocess.Popen:
    """Start one child on the given descriptors and hand it to the caller's wait loop

    A `with` block would wait for the child on any exception, without the loop's timeout and signal
    forwarding, so the loop owns the child.

    @param argv    the whole command
    @param env     the command's environment
    @param out_fd  receives the standard output
    @param err_fd  receives the standard error
    @param group   the arguments that place the child in its process group or session
    @returns       the running child
    """
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out_fd, stderr=err_fd, env=env, close_fds=True,
                            **group)


# Runners -------------------------------------------------------------------

class BaseRunner:
    """The runner of command actions: their environment profiles, their failure policies and the journal

    A subclass starts the children: it supplies `_execute`, `_probe` and `sudo_preflight`.
    """

    def __init__(self, run_dir: RunDir | None = None, console: Console | None = None,
                 host_arch: str = "arm64", environ: Mapping[str, str] | None = None,
                 out_dir: str | None = None) -> None:
        """Start a runner for one command of the tool

        @param run_dir    receives the journal, `commands.log` and the output files; None keeps no record
        @param console    receives the escalated commands and the warnings; None for a default console
        @param host_arch  the hardware architecture
        @param environ    the environment the profiles filter; None for the tool's own
        @param out_dir    the directory of the output files; None for the run's `out` directory, or a
                          temporary one without a run
        """
        self.run_dir = run_dir
        self._out_dir = out_dir
        self.console = console or Console()
        self.host_arch = host_arch
        self.environ: dict[str, str] = dict(os.environ if environ is None else environ)
        self.phase: int | str | None = None
        self.preserve_env_refused = False
        self.notes: list[str] = []
        self.sudo_ready = False
        self.keepalive_failed = False
        self._last_keepalive = float("-inf")   # no keepalive has run yet
        self.interrupted = False
        self.hung_up = False
        self._sigints = 0          # every SIGINT so far; a child gets only those that arrive while it runs
        self._cleanup_depth = 0

    # Paths and journal --------------------------------------------------

    @property
    def out_dir(self) -> str:
        """Return the directory of the output files, created on first use

        @returns  the directory's path
        """
        if self._out_dir is None:
            self._out_dir = self.run_dir.out_dir if self.run_dir else tempfile.mkdtemp(prefix="brew-ports-out-")
        os.makedirs(self._out_dir, exist_ok=True)
        return self._out_dir

    def _out_file(self, journal_id: str, suffix: str) -> str:
        """Return the output file of a command's next attempt, numbered after the attempts already there

        @param journal_id  the command's journal id
        @param suffix      `stdout` or `stderr`
        @returns           the file's path, which does not exist yet
        """
        base = os.path.join(self.out_dir, slug(journal_id))
        attempt = 1
        while os.path.lexists(f"{base}.{attempt}.{suffix}"):
            attempt += 1
        return f"{base}.{attempt}.{suffix}"

    def _journal(self, record: dict[str, object]) -> None:
        """Append a record to the run's journal; a runner without a run directory keeps none

        @param record  a JSON-ready record
        """
        if self.run_dir is not None:
            self.run_dir.journal.append(record)

    def _log(self, journal_id: str, argv: Sequence[str], exit_code: int) -> None:
        """Append the line of a finished command to the run's `commands.log`

        @param journal_id  the command's journal id
        @param argv        the whole command, `sudo` included
        @param exit_code   the command's exit status
        """
        if self.run_dir is None:
            return
        with open(self.run_dir.commands_log, "a", encoding="utf-8") as fh:
            fh.write(f"{now_iso()} [{self.phase}] {journal_id} exit={exit_code} {shlex.join(list(argv))}\n")

    def record_result(self, action: Action, ok: bool) -> None:
        """Journal the action's result line, which `apply --resume` reads

        @param action  the action
        @param ok      whether it succeeded once its failure policy ran
        """
        self._journal({"ts": now_iso(), "phase": self.phase, "action_id": action.action_id,
                       "result": "ok" if ok else "failed"})

    # Signals ------------------------------------------------------------

    @contextlib.contextmanager
    def signals(self) -> Iterator[None]:
        """Install the SIGINT, SIGHUP and SIGTERM handlers for one command

        A SIGINT also reaches the running child; SIGHUP and SIGTERM silence the console. Each of the three
        stops the run at its next check.

        @returns  a context manager that restores the previous handlers when its block ends
        """
        def on_int(_signum, _frame):
            self.note_sigint()

        def on_hup(_signum, _frame):
            self.hung_up = True
            self.console.silenced = True

        saved = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)}
        signal.signal(signal.SIGINT, on_int)
        signal.signal(signal.SIGHUP, on_hup)
        signal.signal(signal.SIGTERM, on_hup)
        try:
            yield
        finally:
            for signum, handler in saved.items():
                signal.signal(signum, handler)

    def note_sigint(self) -> None:
        """Record a SIGINT; a running child gets it forwarded"""
        self.interrupted = True
        self._sigints += 1

    def check_interrupt(self) -> None:
        """Stop the run after an interrupt or a hang-up, unless a `cleanup` block runs

        @throws Interrupted  when SIGINT, SIGHUP or SIGTERM arrived
        """
        if (self.interrupted or self.hung_up) and not self._cleanup_depth:
            raise Interrupted("interrupted")

    @contextlib.contextmanager
    def cleanup(self) -> Iterator[None]:
        """Let a block's commands run despite an interrupt, such as restarting the services a stopped run booted out

        A child gets only the SIGINTs that arrive while it runs; the run stops at the first check after the block.

        @returns  a context manager for the block
        """
        self._cleanup_depth += 1
        try:
            yield
        finally:
            self._cleanup_depth -= 1

    # Running ------------------------------------------------------------

    def env_for(self, action: Action) -> dict[str, str]:
        """Return the environment of an action's command, from its profile and instance

        @param action  the action
        @returns       the child's environment
        """
        return profile_env(action.env_profile, self.environ, prefix=action.instance_prefix)

    def run(self, action: Action, defer_result: bool = False) -> Result:
        """Run a `command` action and apply its failure policy

        @param action             the action; a manual or non-command action is refused
        @param defer_result       leave the result line to the caller, which records it after its own check
        @returns                  the result, whose `ok` holds the outcome once the policy ran
        @throws ActionFailed      when a `STOP` action fails
        @throws EscalationFailed  when sudo itself fails
        @throws Interrupted       when SIGINT, SIGHUP or SIGTERM arrived before a command started
        """
        if action.kind != "command":
            raise ValueError(f"{action.action_id} is a {action.kind} action, not a command")
        if action.manual:
            raise ValueError(f"{action.action_id} is manual: printed, never executed")
        if not action.argv:
            raise ValueError(f"{action.action_id} has an empty argv")
        self.check_interrupt()
        result = self._run_one(action, action.argv, action.action_id, action.dst)
        ok = result.exit == 0
        policy = action.on_failure
        if not ok:
            if policy is OnFailure.STOP:
                result.ok = False
                if not action.read_only:
                    self.record_result(action, False)
                raise ActionFailed(result)
            if policy is OnFailure.SPLIT and action.split_order:
                failed = []
                for name in action.split_order:
                    self.check_interrupt()
                    one = self._run_one(action, split_argv(action, name), f"{action.action_id}.{name}", None)
                    if one.exit != 0:
                        failed.append(name)
                result.failed = failed
                ok = not failed
            elif policy is OnFailure.RETRY_WITH and action.retry_argv:
                self.check_interrupt()
                retry = self._run_one(action, action.retry_argv, action.action_id + ".retry", action.dst)
                result.retry = retry
                ok = retry.exit == 0
                if not ok:
                    result.failed = [action.action_id]
        result.ok = ok
        if not action.read_only and not defer_result:
            self.record_result(action, ok)
        return result

    def _run_one(self, action: Action, argv: Sequence[str], journal_id: str, dst: str | None) -> Result:
        """Run one command of an action and journal it, once more without `--preserve-env` when sudo refuses it

        @param action      the action the command carries out
        @param argv        the command, without sudo
        @param journal_id  the command's journal id
        @param dst         the file that gets stdout, through `<dst>.partial`, when the command succeeds; None
                           for an output file
        @returns           the command's result
        """
        env = self.env_for(action)
        if action.sudo:
            if self.keepalive_failed:
                raise EscalationFailed("the sudo keepalive failed; the cached credentials are gone")
            self.keepalive(force=False)
            full = sudo_argv(argv, env, self.preserve_env_refused)
            self.console.command(full)
        else:
            full = list(argv)
        if dst:
            stdout_path = dst + ".partial"
            with contextlib.suppress(FileNotFoundError):
                os.unlink(stdout_path)          # a leftover of an interrupted attempt
            os.makedirs(os.path.dirname(stdout_path) or ".", exist_ok=True)
        else:
            stdout_path = self._out_file(journal_id, "stdout")
        stderr_path = self._out_file(journal_id, "stderr")
        if action.sudo:
            timeout = None
        elif action.timeout_s is not None:
            timeout = action.timeout_s
        else:
            timeout = PROBE_TIMEOUT_S if action.read_only else None
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        out_fd = os.open(stdout_path, flags, 0o600)
        try:
            err_fd = os.open(stderr_path, flags, 0o600)
            try:
                start = time.monotonic()
                exit_code, timed_out = self._execute(full, env, action, out_fd, err_fd, timeout=timeout,
                                                     journal_id=journal_id)
                duration = time.monotonic() - start
            finally:
                os.close(err_fd)
        finally:
            os.close(out_fd)
        result = Result(journal_id, exit_code, stdout_path, stderr_path, round(duration, 3), timed_out)
        self._journal({"ts": now_iso(), "phase": self.phase, "action_id": journal_id, "argv": full,
                       "sudo": action.sudo, "exit": exit_code, "duration_s": result.duration_s,
                       "stdout_path": stdout_path, "stderr_path": stderr_path,
                       "description": action.description})
        self._log(journal_id, full, exit_code)
        if action.sudo and exit_code == 1:
            lines = result.stderr().splitlines()
            refused = any(line.startswith(PRESERVE_ENV_REFUSAL) for line in lines)
            if refused and any(a.startswith("--preserve-env=") for a in full):
                self.preserve_env_refused = True
                note = ("sudo refuses --preserve-env here, so proxies cannot reach escalated commands; "
                        "set proxy_http and proxy_https in macports.conf")
                if note not in self.notes:
                    self.notes.append(note)
                    self.console.warn(note)
                return self._run_one(action, argv, journal_id, dst)
            failure = next((line for line in lines if line.startswith("sudo: ")), None)
            if failure is not None:
                raise EscalationFailed(f"sudo failed: {failure}", result)
        if exit_code == 0 and dst:
            os.replace(stdout_path, dst)
            result.stdout_path = dst
        return result

    def _execute(self, argv: list[str], env: dict[str, str], action: Action, out_fd: int, err_fd: int, *,
                 timeout: float | None, journal_id: str) -> tuple[int, bool]:
        """Run one command to its end

        @param argv        the whole command, `sudo` included
        @param env         the command's environment
        @param action      the action the command carries out
        @param out_fd      receives the standard output
        @param err_fd      receives the standard error
        @param timeout     the seconds after which the command is killed; None for no limit
        @param journal_id  the command's journal id
        @returns           the exit status, and whether the timeout killed the command
        """
        raise NotImplementedError

    # sudo ----------------------------------------------------------------

    def keepalive(self, force: bool = False) -> None:
        """Run `sudo -n -v` once sudo is ready and the last one is older than 60 s

        A failure sets `keepalive_failed`, which refuses every later sudo command.

        @param force  run it whatever the age of the last one
        """
        if not self.sudo_ready:
            return
        now = time.monotonic()
        if not force and now - self._last_keepalive < KEEPALIVE_S:
            return
        self._last_keepalive = now
        if self._probe([SUDO, "-n", "-v"]) != 0:
            self.keepalive_failed = True

    def _probe(self, argv: list[str]) -> int:
        """Run a short internal probe in its own process group, such as the keepalive or `sudo -n true`

        @param argv  the probe's command
        @returns     its exit status
        """
        raise NotImplementedError

    def sudo_preflight(self) -> None:
        """Cache sudo credentials: `sudo -v` (terminal) or `sudo -A -v` (SUDO_ASKPASS), then `sudo -n true`

        @throws PreflightError  when sudo caches no credentials
        """
        raise NotImplementedError


class CommandRunner(BaseRunner):
    """A runner of real children, each in its own process group, waited for in one-second slices"""

    def _execute(self, argv, env, action, out_fd, err_fd, *, timeout, journal_id):
        """Run the command as a child in a process group of its own, waited for in one-second slices

        The first interrupt is forwarded to the child's group, and the timeout kills the group.

        @param argv        the whole command, `sudo` included
        @param env         the command's environment
        @param action      the action the command carries out
        @param out_fd      receives the standard output
        @param err_fd      receives the standard error
        @param timeout     the seconds after which the group is killed; None for no limit
        @param journal_id  the command's journal id, for the record of a forwarded interrupt
        @returns           the exit status, and whether the timeout killed the command
        """
        if action.new_session and (action.sudo or not action.read_only):
            raise ValueError(f"{action.action_id}: only a read-only probe without sudo runs in a new session")
        # The login shell PATH check runs the user's login shell without a controlling
        # terminal, in a session of its own; everything else stays in the tool's session.
        group: _GroupKwargs = {"start_new_session": True} if action.new_session else _group_kwargs()
        try:
            proc = _spawn(argv, env, out_fd, err_fd, group)
        except OSError as exc:
            # A program that cannot be started is a failed command, as in a shell.
            os.write(err_fd, (f"{argv[0]}: {exc.strerror or exc}\n").encode("utf-8"))
            return (127 if isinstance(exc, FileNotFoundError) else 126), False
        pgid = proc.pid
        start = time.monotonic()
        sigints_at_start = self._sigints
        forwarded = False
        timed_out = False
        while True:
            try:
                exit_code = proc.wait(timeout=1)
                break
            except subprocess.TimeoutExpired:
                pass
            if self._sigints != sigints_at_start and not forwarded:
                forwarded = True
                self._forward_interrupt(action, pgid, journal_id)
            if timeout is not None and not timed_out and time.monotonic() - start > timeout:
                timed_out = True
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(pgid, signal.SIGKILL)
            self.keepalive(force=False)
        return exit_code, timed_out

    def _forward_interrupt(self, action: Action, pgid: int, journal_id: str) -> None:
        """Forward SIGINT to the child's process group

        An escalated child runs as root, and sudo without a pseudo-terminal relays a user's signal to
        the command alone, so its group gets the signal from a root `kill`.

        @param action      the action the child carries out
        @param pgid        the child's process group
        @param journal_id  the command's journal id, for the record of the root `kill`
        """
        if not action.sudo:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pgid, signal.SIGINT)
            return
        argv = [SUDO, "-n", KILL, "-s", "INT", "--", f"-{pgid}"]
        code = self._probe(argv)
        self._journal({"ts": now_iso(), "phase": self.phase, "action_id": journal_id + ".interrupt",
                       "argv": argv, "sudo": True, "exit": code, "description": "interrupt the escalated command"})
        if code != 0:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pgid, signal.SIGINT)
            self.console.warn("could not interrupt the escalated command as root; it may run to its end")

    def _probe(self, argv: list[str]) -> int:
        """Run a probe in its own process group, with the neutral environment and no input or output

        @param argv  the probe's command
        @returns     its exit status; 255 when it cannot start or outlives the probe timeout
        """
        env = profile_env("neutral", self.environ)
        try:
            return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, env=env, timeout=PROBE_TIMEOUT_S, check=False,
                                  **_group_kwargs()).returncode
        except (OSError, subprocess.TimeoutExpired):
            return 255

    def sudo_preflight(self) -> None:
        """Have sudo cache credentials for this process, from the terminal or SUDO_ASKPASS

        @throws PreflightError  when sudo holds no cached credentials afterwards
        """
        env = profile_env("neutral", self.environ)
        has_tty = sys.stdin.isatty()
        askpass = bool(self.environ.get("SUDO_ASKPASS"))
        if has_tty:
            # The foreground process group, so sudo can prompt on the terminal.
            subprocess.call([SUDO, "-v"], env=env)
        elif askpass:
            subprocess.call([SUDO, "-A", "-v"], stdin=subprocess.DEVNULL, env=env, **_group_kwargs())
        self.check_interrupt()
        if self._probe([SUDO, "-n", "true"]) != 0:
            if not has_tty and not askpass:
                raise PreflightError(
                    "sudo needs a password and there is no terminal and no SUDO_ASKPASS: set SUDO_ASKPASS, "
                    "or run brew-ports from a terminal (a ticket made by another process is not this one's)")
            raise PreflightError(
                "sudo did not cache credentials (wrong password, or timestamp_timeout 0 in sudoers)")
        self.sudo_ready = True
        self._last_keepalive = time.monotonic()


def command_runner(ctx: Context, run_dir: RunDir | None) -> CommandRunner:
    """Return the `CommandRunner` of one command, with the host architecture probed

    @param ctx      the command's context, for its console and environment
    @param run_dir  the run directory; None for a command that keeps no run
    @returns        the runner
    """
    runner = CommandRunner(run_dir=run_dir, console=ctx.console, environ=ctx.environ)
    runner.host_arch = system.host_arch(runner)
    return runner


def start_run(ctx: Context, phase: int | str | None,
              make_runner: Callable[[Context, RunDir], BaseRunner] | None = None) -> tuple[RunDir, BaseRunner]:
    """Open the run directory and the runner of one command

    @param ctx          the command's context; its `runner` becomes the new runner
    @param phase        the phase the runner journals its commands under, an apply phase or `rollback`;
                        None outside them
    @param make_runner  builds the runner from the context and the run directory; None for `command_runner`
    @returns            the run directory and the runner
    """
    run_dir = ctx.state.new_run()
    runner = (make_runner or command_runner)(ctx, run_dir)
    ctx.runner = runner
    runner.phase = phase
    return run_dir, runner


@dataclass
class FakeResponse:
    """The canned outcome of one fake command"""

    exit: int = 0
    stdout: str = ""
    stderr: str = ""


Responder = FakeResponse | list[FakeResponse] | Callable[[tuple[str, ...]], FakeResponse]


class FakeRunner(BaseRunner):
    """Replays canned outputs keyed by argv after placeholder replacement

    Placeholders such as `<run>` and `<id>` replace the run directory and run id before the lookup,
    so fixtures stay stable; a list of responses is consumed one per call.
    """

    def __init__(self, responses: Mapping[Sequence[str], Responder] | None = None,
                 default: Responder | None = None, placeholders: Mapping[str, str] | None = None,
                 sudo_ok: bool = True, **kwargs) -> None:
        """Start a fake runner

        @param responses     the canned responses, keyed by argv with the placeholders put in
        @param default       the responder for a command not listed, of any form `responses` takes; None refuses
                             such a command
        @param placeholders  further real texts, each mapped to its placeholder
        @param sudo_ok       whether the sudo probes and the sudo preflight succeed
        @param kwargs        the `BaseRunner` arguments
        """
        super().__init__(**kwargs)
        self.responses: dict[tuple[str, ...], Responder] = {tuple(k): v for k, v in (responses or {}).items()}
        self.default = default
        self.placeholders: dict[str, str] = dict(placeholders or {})
        if self.run_dir is not None:
            self.placeholders.setdefault(self.run_dir.path, "<run>")
            self.placeholders.setdefault(self.run_dir.run_id, "<id>")
        self.calls: list[tuple[str, ...]] = []
        self.sudo_ok = sudo_ok

    def key(self, argv: Sequence[str]) -> tuple[str, ...]:
        """Return an argv with its placeholders put in, longest value first, as the responses are keyed

        @param argv  the command
        @returns     the key
        """
        order = sorted(self.placeholders.items(), key=lambda kv: -len(kv[0]))
        out = []
        for arg in argv:
            for real, holder in order:
                if real:
                    arg = arg.replace(real, holder)
            out.append(arg)
        return tuple(out)

    def respond(self, argv: Sequence[str]) -> FakeResponse:
        """Record the call and return its canned response

        @param argv       the command
        @returns          the response
        @throws KeyError  when the command has no response, or its list of responses is used up
        """
        key = self.key(argv)
        self.calls.append(key)
        resp = self.responses.get(key, self.default)
        if isinstance(resp, list):
            if not resp:
                raise KeyError(f"FakeRunner: responses for {key!r} are used up")
            resp = resp.pop(0)
        elif callable(resp):
            resp = resp(key)
        if resp is None:
            raise KeyError(f"FakeRunner: no response for {key!r}")
        return resp

    def _execute(self, argv, env, action, out_fd, err_fd, *, timeout, journal_id):
        """Write the canned response of the command to the two descriptors

        @param argv        the whole command, `sudo` included, which selects the response
        @param env         the command's environment, which the response ignores
        @param action      the action the command carries out, which the response ignores
        @param out_fd      receives the canned standard output
        @param err_fd      receives the canned standard error
        @param timeout     the timeout, which the response ignores
        @param journal_id  the command's journal id, which the response ignores
        @returns           the canned exit status, never timed out
        """
        resp = self.respond(argv)
        os.write(out_fd, resp.stdout.encode("utf-8"))
        os.write(err_fd, resp.stderr.encode("utf-8"))
        return resp.exit, False

    def _probe(self, argv: list[str]) -> int:
        """Record a probe and answer it: a sudo probe follows `sudo_ok`, any other succeeds

        @param argv  the probe's command
        @returns     0, or 1 for a sudo probe when `sudo_ok` is unset
        """
        self.calls.append(self.key(argv))
        if argv[:2] == [SUDO, "-n"]:
            return 0 if self.sudo_ok else 1
        return 0

    def sudo_preflight(self) -> None:
        """Pretend that sudo cached credentials, as `sudo_ok` decides

        @throws PreflightError  when `sudo_ok` is unset
        """
        if not self.sudo_ok:
            raise PreflightError("sudo did not cache credentials")
        self.sudo_ready = True
        self._last_keepalive = time.monotonic()


# Root-owned files -----------------------------------------------------------

class StagingError(RunnerError):
    """The root staging directory or a staged copy is not what root may consume"""


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 of some bytes

    @param data  the bytes
    @returns     the digest in lowercase hex
    """
    return hashlib.sha256(data).hexdigest()


class RootFiles:
    """The root staging directory, the root backup store and the root form of the `write` action

    Root consumes only files the tool checked in this process: each is copied into the root-owned
    staging directory with `sudo install -m 0644` and checked there first.
    """

    STAGING_PARENT = "/private/var/tmp"
    STORE_PARENT = "/private/var/db/brew-ports"

    def __init__(self, runner: BaseRunner, run_id: str) -> None:
        """Start the root files of one run; each directory is created when a step first needs it

        @param runner  the runner of the escalated commands
        @param run_id  the run's id, which names its root backup store
        """
        self.runner = runner
        self.run_id = run_id
        self.staging: str | None = None
        self._store_made = False

    def _action(self, step: str, argv: list[str], description: str, probe: bool = False) -> Action:
        """Build an escalated action of the runner's current phase

        @param step         the step, which ends the `<phase>.root.<step>` action id
        @param argv         the command, without sudo
        @param description  what the command does
        @param probe        whether a failure is data rather than a stop
        @returns            the action
        """
        return Action(action_id=f"{self.runner.phase}.root.{step}", kind="command", argv=argv,
                      sudo=True, description=description,
                      on_failure=OnFailure.PROBE if probe else OnFailure.STOP)

    def staging_dir(self) -> str:
        """Return the root staging directory, created under a random name the first time

        @returns              the directory's path
        @throws StagingError  when the directory made is not a root-owned directory with mode 0755
        """
        if self.staging:
            return self.staging
        path = f"{self.STAGING_PARENT}/brew-ports.{secrets.token_hex(8)}"
        self.runner.run(self._action("staging.mkdir", [MKDIR, "-m", "0755", path], "create the root staging directory"))
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o755:
            raise StagingError(f"{path} is not a root-owned directory with mode 0755")
        self.staging = path
        return path

    def stage(self, src: str, name: str, sha256: str | None = None) -> str:
        """Copy a file into the staging directory and verify the copy

        @param src            the file to stage
        @param name           the copy's name in the staging directory
        @param sha256         the digest the copy must have; None skips the comparison
        @returns              the staged copy's path
        @throws StagingError  when the copy is not a root-owned regular file, or its digest differs
        """
        dest = os.path.join(self.staging_dir(), name)
        self.runner.run(self._action(f"stage.{slug(name)}", [INSTALL, "-m", "0644", src, dest],
                                     f"stage {name} for root"))
        st = os.lstat(dest)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
            raise StagingError(f"{dest} is not a root-owned regular file")
        if sha256 is not None:
            with open(dest, "rb") as fh:
                if sha256_bytes(fh.read()) != sha256:
                    raise StagingError(f"the staged copy of {name} does not match what the tool wrote")
        return dest

    def remove_staging(self) -> None:
        """Remove the root staging directory when one was made; a failed removal does not stop the run"""
        if self.staging:
            self.runner.run(self._action("staging.rm", [RM, "-rf", self.staging], "remove the root staging directory",
                                         probe=True))
            self.staging = None

    @property
    def store(self) -> str:
        """Return the run's root backup store

        @returns  `/private/var/db/brew-ports/<run_id>`
        """
        return f"{self.STORE_PARENT}/{self.run_id}"

    def backup(self, path: str) -> str:
        """Copy a root-owned file into the root backup store with `sudo cp -n -p`, so the first copy stays

        macOS `cp -n` exits 1 when the copy exists, as it does on a resumed run; the copy the store holds stands.

        @param path           the file
        @returns              the copy's path in the store
        @throws ActionFailed  when the store cannot be created, or the copy fails and the store holds none
        """
        if not self._store_made:
            self.runner.run(self._action("store.mkdir", [MKDIR, "-p", "-m", "0700", self.store],
                                         "create the root backup store"))
            self._store_made = True
        dest = f"{self.store}/{slug(path)}"
        copy = self._action(f"store.{slug(path)}", [CP, "-n", "-p", path, dest],
                            f"back up {path} into the root backup store", probe=True)
        result = self.runner.run(copy, defer_result=True)
        held = self._action(f"store.{slug(path)}.held", [TEST, "-f", dest],
                            f"look for the earlier copy of {path} in the root backup store", probe=True)
        ok = result.exit == 0 or self.runner.run(held).exit == 0
        self.runner.record_result(copy, ok)
        if not ok:
            raise ActionFailed(result)
        return dest

    def write(self, path: str, content: str, tmp_dir: str) -> str:
        """Run the root form of the `write` action: back up, stage, verify and install the file

        @param path           the root-owned file to rewrite, which must exist
        @param content        the file's new text
        @param tmp_dir        a directory the user may write, for the copy that is staged
        @returns              the SHA-256 of the new content
        @throws ActionFailed  when an escalated step fails
        @throws StagingError  when the staged copy fails its check
        """
        st = os.stat(path)
        self.backup(path)
        data = content.encode("utf-8")
        digest = sha256_bytes(data)
        fd, tmp = tempfile.mkstemp(prefix="brew-ports-write-", dir=tmp_dir)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            staged = self.stage(tmp, slug(path), sha256=digest)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
        mode = f"{stat.S_IMODE(st.st_mode):o}"
        self.runner.run(self._action(f"install.{slug(path)}",
                                     [INSTALL, "-m", mode, "-o", str(st.st_uid), "-g", str(st.st_gid), staged, path],
                                     f"install the rewritten {path}"))
        return digest

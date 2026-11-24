# Architecture

brew-ports is one Python package, `brew_ports`. `cli.py` parses the command
line and hands one command module a `Context` (`context.py`). Every command except `bootstrap-ports` reads
the host through one inventory, and every external program runs through one module, `runner.py`.

## From scan to rollback

Each command lives in one module:

| Command | Main module | What it adds |
| --- | --- | --- |
| `scan` | `scan.py` | The inventory of every instance and of the shell environment, written to `scan.json`. |
| `doctor` | `doctor.py` | The findings: system and environment checks here, manager checks in `homebrew/health.py` and `macports/health.py`. With `--target`, `doctor_target.py` picks the installation that stays and `duplicates.py` finds the packages that are installed twice. |
| `recommend` | `recommend.py` | Both migration directions, scored from the scan and the findings. |
| `bootstrap-ports` | `macports/bootstrap.py` | MacPorts base, installed from its signed package. |
| `plan` | `planner.py` | `plan.json`, with the mappings, the package sets, and the phases, or `plan-refused.json` with its reasons. |
| `apply` | `executor.py` | Phases 0 to 8 of a plan. |
| `verify` | `verify.py` | The checks of phase 8, and the phase 4 gate. |
| `env-cleanup` | `envclean.py` | The shell-file and `/etc/paths` edits of phase 7, run alone. |
| `rollback` | `rollback.py` | The reinstall of what a run removed, from its snapshot. |

Commands that follow a scan reuse it for ten minutes. A command that changes
the host leaves a dirty marker, which ends the reuse, and `apply` refuses a plan
older than the marker.

## The layers

Every layer uses processes and state, and the run uses every layer.

### Processes and state

`runner.py` is the only module that starts a process. Each one is an `Action`
record from `model.py`, with an absolute argv, an environment profile, and a
failure policy. A policy stops the run, returns the exit status as data, splits
a batch into one command per name, or retries with another argv.

Each child runs in a separate process group inside the tool's session. Only the
read-only probe of the login shell's `PATH` gets a separate session. Ctrl-C
reaches the group, and the runner waits for the child to exit. `sudo` runs per
command, with `-n`.

`state.py` owns the state directory and each run's journal.

`progress.py` draws the status line on a terminal. A thread redraws it ten times
a second, so it keeps moving through a long command and through the tool's own
work between commands. The runner names each command on it, and the scan and the
checks name their steps and count the files they read. Each console write and
each prompt clears it first.

### The managers

`homebrew/` and `macports/` share five parts:

- `locate.py` finds the instances and decides whether each one can be driven.
- The catalog (`catalogue.py`, `portindex.py`) answers offline what the target
  offers.
- `inventory.py` lists the packages each instance holds.
- `actions.py` builds every command the tool runs against that manager.
- `health.py` holds the manager's findings and repairs.

`macports/registry.py` reads the registry from a SQLite backup, never from the
live file.

### The environment

`env/` reads what spans both managers:

- `shell.py` reads the shell files without running them.
- `linkage.py` reads load commands with `otool -l`.
- `services.py` maps each service plist to its package and its loaded job.
- `interpreters.py` lists the pip, pipx, npm, gem, and cpan installs.

`env.PrefixIndex` answers the question all of them ask: which instance a path
belongs to.

### The decisions

`equiv/` maps a source package to its target. It matches by name rules, by the
curated pairs of `data/equivalents.json`, by executables and homepages, and,
under `--repology`, by Repology. `plan_sets.py` derives the kept and removal
sets from the roots the user installed on purpose. `plan_phases.py` writes
phases 2 and 3 into the plan and previews phase 6. `apply` computes the other
phases when they run.

### The run

`executor.py` runs phase 0 and drives the others, with the state `exec_run.py`
keeps per start of a run:

- `snapshot.py` writes phase 1, and reads it back for `rollback.py`.
- `exec_install.py` runs phases 2 and 3.
- `verify.py` runs the phase 4 gate and phase 8.
- `exec_remove.py` runs phase 5.
- `remove_manager.py` runs phase 6.
- `exec_env.py` and `envclean.py` run phase 7.

`servicectl.py` stops and restarts services.

## Rules the code keeps

A change keeps these invariants:

- The run removes nothing before phase 4 passes: each replacement exists in the
  target, provides its commands, and links cleanly.
- The code compares paths by file identity wherever the path exists. Text
  decides only for a path that is gone.
- Phase 6 tests every path against the safety rules of `plan_phases.unsafe`,
  which `remove_manager.py` extends, before removing it.
- `brew` never runs under `sudo`.
- On `apply --resume`, phases 1 to 3 skip the work that succeeded. The later
  phases recompute the remaining work from the host.

## State on disk

The state directory, `~/Library/Application Support/brew-ports/` by default,
holds these files:

- `runs/<run-id>/` holds one directory per command run.
- `latest` links to the newest run.
- `lock` admits one brew-ports at a time.
- `dirty` records the last command that changed the host.

A run directory holds, depending on the command:

- `scan.json`, and `plan.json` for a `plan` or `apply` run
- `journal.jsonl` and `commands.log`
- `snapshot/`, the phase 1 snapshot
- `backup/`, the original of every file the run edits
- `report.md`, with the user's home directory and login name redacted

## Tests

The unit tests under `tests/unit/` never start `brew`, `port`, or `sudo`.
`FakeRunner` answers each argv from a table, and the fixtures build instances,
registries, and catalogs in a temporary directory. Tests of process groups or file identity use the real file system,
through `TempDirTest` in `tests/unit/helpers.py`.
